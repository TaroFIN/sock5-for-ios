import asyncio
import logging
import ipaddress
import struct
import socket  # 用於 UDP socket
import uuid  # 用於生成連線 ID

# TCP/UDP connection classes for logging and management
class TCPConnection:
    def __init__(self, client_addr, dst_addr, dst_port):
        self.conn_id = uuid.uuid4().hex[:8]  # 生成唯一 ID（取前8位簡化）
        self.client_addr = client_addr
        self.dst_addr = dst_addr
        self.dst_port = dst_port
    def close(self):
        pass

class UDPConnection:
    def __init__(self, client_addr, bound_addr, bound_port):
        self.conn_id = uuid.uuid4().hex[:8]  # 生成唯一 ID（取前8位簡化）
        self.client_addr = client_addr
        self.bound_addr = bound_addr
        self.bound_port = bound_port
    def close(self):
        pass

async def handle_data(reader, writer):
    """
    Handles data transfer for one direction.
    """
    while True:
        try:
            # Use a timeout to prevent idle connections from hanging forever.
            data = await asyncio.wait_for(reader.read(4096), timeout=1800)  # 30分鐘
            if not data:
                break
            writer.write(data)
            await writer.drain()
        except (asyncio.TimeoutError, ConnectionError, asyncio.CancelledError) as e:
            # Catching these exceptions ensures the loop breaks cleanly.
            break

async def handle_socks5(reader, writer):
    """
    Handles a single SOCKS5 connection.
    """
    loop = asyncio.get_running_loop()  # 用於 async 操作
    udp_transport = None  # 初始化 UDP transport 變數
    try:
        # SOCKS5 greeting
        # Read the first two bytes: protocol version and number of auth methods
        data = await reader.readexactly(2)
        if data[0] != 0x05:
            logging.error("Invalid SOCKS protocol version: %d", data[0])
            writer.close()
            await writer.wait_closed()
            return

        num_methods = data[1]
        methods = await reader.readexactly(num_methods)
        if 0x00 not in methods:
            # No acceptable authentication method
            reply = bytearray([0x05, 0xFF])
            writer.write(reply)
            await writer.drain()
            writer.close()
            await writer.wait_closed()
            return

        # Reply with no-auth method
        reply = bytearray([0x05, 0x00])
        writer.write(reply)
        await writer.drain()

        # SOCKS5 request
        # Read the first 4 bytes: version, command, reserved, address type
        request_data = await reader.readexactly(4)
        ver, cmd, rsv, atyp = struct.unpack("!BBBB", request_data)

        if ver != 0x05:
            logging.error("Invalid SOCKS protocol version in request: %d", ver)
            writer.close()
            await writer.wait_closed()
            return
        
        if cmd == 0x01:
            # CONNECT (TCP)
            pass  # continue below
        elif cmd == 0x03:
            # UDP ASSOCIATE
            bound_addr = '0.0.0.0'  # 綁定到所有介面
            bound_port = 0  # 系統自動分配
            
            # 定義 UDP Protocol 類別
            class UDPProtocol(asyncio.DatagramProtocol):
                def __init__(self):
                    self.client_addrs = set()  # 追蹤客戶端位址
                    self.tasks = set()  # 追蹤所有 handle_datagram 任務
                    self.sem = asyncio.Semaphore(50)  # 新增：限制並發轉發，調整數字以匹配系統限制
                    
                def connection_made(self, transport):
                    self.transport = transport
                    sock = transport.get_extra_info('socket')
                    actual_bound_addr, actual_bound_port = sock.getsockname()
                
                def datagram_received(self, data, addr):
                    if addr not in self.client_addrs:
                        self.client_addrs.add(addr)
                    task = asyncio.create_task(self.handle_datagram(data, addr))
                    self.tasks.add(task)
                    task.add_done_callback(self.tasks.discard)
                
                async def handle_datagram(self, data, addr):
                    async with self.sem:  # 限制並發
                        try:
                            if len(data) < 10:
                                return
                            rsv, frag, atyp = struct.unpack("!HBB", data[:4])
                            if frag != 0:
                                return
                            offset = 4
                            if atyp == 0x01:
                                dst_addr = ipaddress.IPv4Address(data[offset:offset+4]).exploded
                                offset += 4
                            elif atyp == 0x03:
                                dlen = data[offset]
                                dst_addr = data[offset+1:offset+1+dlen].decode('utf-8')
                                offset += 1 + dlen
                            else:
                                return
                            dst_port = struct.unpack("!H", data[offset:offset+2])[0]
                            payload = data[offset+2:]
                            
                            def forward_and_receive():
                                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as dst_sock:
                                    dst_sock.settimeout(5)
                                    dst_sock.sendto(payload, (dst_addr, dst_port))
                                    resp, src_addr = dst_sock.recvfrom(4096)
                                    return resp, src_addr
                            
                            resp, src_addr = await loop.run_in_executor(None, forward_and_receive)
                            
                            header = struct.pack("!HBB", 0, 0, 0x01) + ipaddress.IPv4Address(src_addr[0]).packed + struct.pack("!H", src_addr[1])
                            self.transport.sendto(header + resp, addr)
                        except socket.timeout:
                            logging.error(f"[UDP] Timeout waiting for response from {dst_addr}:{dst_port}")
                        except Exception as e:
                            logging.error(f"[UDP] Error in relay: {e}")
                        except asyncio.CancelledError:
                            pass  # 忽略取消錯誤
                
                def connection_lost(self, exc):
                    # 當連線丟失時，取消所有任務
                    for task in list(self.tasks):
                        task.cancel()
            
            # 建立 UDP endpoint，並獲取實際端口
            udp_transport, protocol = await loop.create_datagram_endpoint(
                lambda: UDPProtocol(),
                local_addr=(bound_addr, bound_port)
            )
            actual_bound_addr, actual_bound_port = udp_transport.get_extra_info('socket').getsockname()
            
            # 發送回應
            reply = bytearray([0x05, 0x00, 0x00, 0x01]) + ipaddress.IPv4Address(actual_bound_addr).packed + struct.pack("!H", actual_bound_port)
            writer.write(reply)
            await writer.drain()
            
            # log UDP connection
            client_addr = writer.get_extra_info('peername')
            udp_conn = UDPConnection(client_addr, actual_bound_addr, actual_bound_port)
            
            # 保持 TCP 開啟
            try:
                await asyncio.wait_for(reader.read(1), timeout=1800)
            except asyncio.TimeoutError:
                pass
            return
            
        else:
            # 不支援的cmd
            reply = bytearray([0x05, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
            writer.write(reply)
            await writer.drain()
            writer.close()
            await writer.wait_closed()
            return
        
        dst_addr = None
        dst_port = None

        if atyp == 0x01: # IPv4
            addr_data = await reader.readexactly(4)
            dst_addr = ipaddress.IPv4Address(addr_data)
        elif atyp == 0x03: # Domain name
            len_data = await reader.readexactly(1)
            domain_len = struct.unpack("!B", len_data)[0]
            domain_data = await reader.readexactly(domain_len)
            dst_addr = domain_data.decode('utf-8')
        else: # Unsupported address type
            reply = bytearray([0x05, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
            writer.write(reply)
            await writer.drain()
            writer.close()
            await writer.wait_closed()
            return

        # Read the port
        port_data = await reader.readexactly(2)
        dst_port = struct.unpack("!H", port_data)[0]

        # Connect to the destination
        try:
            peer_reader, peer_writer = await asyncio.open_connection(str(dst_addr), dst_port)
            
            # Send success reply
            bound_addr = ipaddress.IPv4Address('0.0.0.0')
            bound_port = 0
            reply = bytearray([0x05, 0x00, 0x00, 0x01]) + bound_addr.packed + struct.pack("!H", bound_port)
            writer.write(reply)
            await writer.drain()
            
            # log TCP connection
            client_addr = writer.get_extra_info('peername')
            tcp_conn = TCPConnection(client_addr, dst_addr, dst_port)
            
            # Bidirectional data transfer
            client_to_peer = asyncio.create_task(handle_data(reader, peer_writer))
            peer_to_client = asyncio.create_task(handle_data(peer_reader, writer))

            done, pending = await asyncio.wait(
                [client_to_peer, peer_to_client],
                return_when=asyncio.FIRST_COMPLETED
            )
            
            for task in pending:
                task.cancel()
            
            await asyncio.gather(*pending, return_exceptions=True)
            
            tcp_conn.close()

        except ConnectionRefusedError:
            logging.error("Connection to %s:%d refused", dst_addr, dst_port)
            reply = bytearray([0x05, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
            writer.write(reply)
            await writer.drain()
        except Exception as e:
            logging.error("An error occurred during proxying: %s", e)
            reply = bytearray([0x05, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
            writer.write(reply)
            await writer.drain()
        
    finally:
        if not writer.is_closing():
            writer.close()
            await writer.wait_closed()
        if 'peer_writer' in locals() and not peer_writer.is_closing():
            peer_writer.close()
            await peer_writer.wait_closed()
        if udp_transport:
            udp_transport.close()
            # 等待 UDP protocol 的任務完成
            if hasattr(protocol, 'tasks'):
                for task in list(protocol.tasks):
                    task.cancel()
                await asyncio.gather(*protocol.tasks, return_exceptions=True)
        if 'udp_conn' in locals():
            udp_conn.close()

async def main():
    """
    Main function to run the SOCKS5 server.
    """
    logging.basicConfig(level=logging.ERROR)
    try:
        server = await asyncio.start_server(
            handle_socks5, '172.20.10.1', 9876
        )
        addr = server.sockets[0].getsockname()
        
        async with server:
            await server.serve_forever()
    except Exception as e:
        logging.error("Server failed: %s", e)

if __name__ == "__main__":
    asyncio.run(main())