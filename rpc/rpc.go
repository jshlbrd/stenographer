// Package rpc implements an optional, secure gRPC server.
package rpc

import (
        "crypto/tls"
        "crypto/x509"
        "fmt"
        "io"
        "io/ioutil"
        "log"
        "net"
        "os"
        "os/exec"
        "path/filepath"
        "google.golang.org/grpc"
        "google.golang.org/grpc/credentials"

        "github.com/google/stenographer/config"
        pb "github.com/google/stenographer/protobuf"
)


// gRPC server which takes the RpcConfig.
type stenographerServer struct {
        rpcCfg *config.RpcConfig
}

// Implements RetrievePcap call which takes a client query request, applies it
// to stenoread, and streams the PCAP back to the client.
func (s *stenographerServer) RetrievePcap(
        req *pb.PcapRequest,
        stream pb.Stenographer_RetrievePcapServer,
) error {
        if req.Query == nil {
                return nil
        }

        chunkSize := s.rpcCfg.PcapClientChunkSize
        if req.ChunkSize != nil {
                chunkSize = req.ChunkSize
        }

        maxSize := s.rpcCfg.PcapClientChunkSize
        if req.MaxSize != nil {
                maxSize = req.MaxSize
        }

        pcapPath := filepath.Join(s.rpcCfg.PcapPath, fmt.Sprintf("%s.pcap", req.Uid))
        cmd := exec.Command("stenoread", req.Query, "-w", pcapPath)
        if err := cmd.Run(); err != nil {
                log.Printf("Rpc: Unable to run stenoread command: %v", err)
                return nil
        }
        pcapFile, err := os.Open(pcapPath)
        if err != nil {
                log.Printf("Rpc: Unable to open PCAP file %s: %v", pcapPath, err)
                return nil
        }

        var pcapOffset int32 = 0
        buffer := make([]byte, chunkSize)
        for pcapOffset < maxSize {
                if pcapOffset >= s.rpcCfg.PcapLimitSize {
                        log.Printf("Rpc: Request %s hit size limit %d", req.Uid, s.rpcCfg.PcapLimitSize)
                        break
                }

                pcapOffset += chunkSize
                bytesread, err := pcapFile.Read(buffer)
                if err != nil {
                        if err != io.EOF {
                                log.Printf("Rpc: Non-EOF error when reading PCAP %s: %v", pcapPath, err)
                        }
                        break
                }

                stream.Send(&pb.PcapResponse{Uid: req.Uid, Pcap: buffer[:bytesread]})
        }

        if err := pcapFile.Close(); err != nil {
                log.Printf("Rpc: Unable to close PCAP file %s: %v", pcapPath, err)
        }
        if err := os.Remove(pcapPath); err != nil {
                log.Printf("Rpc: Unable to remove PCAP file %s: %v", pcapPath, err)
        }

        return nil
}

// Called from main via goroutine, this function opens the gRPC port, loads
// certificates, and runs the gRPC server.
func RunStenorpc(rpcCfg *config.RpcConfig) {
        log.Print("Starting stenorpc")
        listener, err := net.Listen("tcp", fmt.Sprintf(":%d", rpcCfg.Port))
        if err != nil {
                log.Printf("Rpc: Failed to start server: %v", err)
                return
        }

        cert, err := tls.LoadX509KeyPair(
                rpcCfg.ServerCert,
                rpcCfg.ServerKey,
        )
        if err != nil {
                log.Printf("Rpc: Failed to load server key pair: %v", err)
                return
        }
        pool := x509.NewCertPool()
        caCert, err := ioutil.ReadFile(rpcCfg.CaCert)
        if err != nil {
                log.Printf("Rpc: Failed to read CA certificate: %v", err)
                return
        }
        ok := pool.AppendCertsFromPEM(caCert)
        if !ok {
                log.Printf("Rpc: Failed to append CA certificate: %v", err)
                return
        }
        tlsCfg := &tls.Config{
                ClientAuth:   tls.RequireAndVerifyClientCert,
                Certificates: []tls.Certificate{cert},
                ClientCAs:    pool,
        }

        tlsCreds := grpc.Creds(credentials.NewTLS(tlsCfg))
        grpcServer := grpc.NewServer(tlsCreds)
        pb.RegisterStenographerServer(grpcServer, &stenographerServer{rpcCfg: rpcCfg})
        if err := grpcServer.Serve(listener); err != nil {
                log.Printf("Rpc: Failed to run gRPC server: %v", err)
                return
        }
}
