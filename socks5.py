import asyncio
import logging
import ipaddress
import struct

# Global connection counter and lock
active_connections = 0
active_connections_lock = asyncio.Lock()

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
    global active_connections
    try:
        # Increase connection count
        async with active_connections_lock:
            active_connections += 1
            logging.info(f"Active connections: {active_connections}")

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
        
        if cmd != 0x01:
            # Only support CONNECT command
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

        logging.info("Connecting to %s:%d", dst_addr, dst_port)

        # Connect to the destination
        try:
            peer_reader, peer_writer = await asyncio.open_connection(str(dst_addr), dst_port)
            
            # Send success reply
            # We use 127.0.0.1 for the bound address and a dummy port.
            bound_addr = ipaddress.IPv4Address('127.0.0.1')
            bound_port = 55555
            reply = bytearray([0x05, 0x00, 0x00, 0x01]) + bound_addr.packed + struct.pack("!H", bound_port)
            writer.write(reply)
            await writer.drain()
            
            # --- START OF MODIFIED LOGIC ---
            # Create tasks for bidirectional data transfer.
            client_to_peer = asyncio.create_task(handle_data(reader, peer_writer))
            peer_to_client = asyncio.create_task(handle_data(peer_reader, writer))

            # Wait for either task to complete, then cancel the other.
            done, pending = await asyncio.wait(
                [client_to_peer, peer_to_client],
                return_when=asyncio.FIRST_COMPLETED
            )
            
            # Cancel any pending tasks to ensure all resources are released.
            for task in pending:
                task.cancel()
            
            # Wait for the cancellation to be acknowledged to prevent resource leaks.
            await asyncio.gather(*pending, return_exceptions=True)
            # --- END OF MODIFIED LOGIC ---

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
        # Ensure all connections are closed when the main task is done.
        # This handles cases where exceptions were not caught or tasks were cancelled.
        if not writer.is_closing():
            writer.close()
            await writer.wait_closed()
        if 'peer_writer' in locals() and not peer_writer.is_closing():
            peer_writer.close()
            await peer_writer.wait_closed()
        # Decrease connection count
        async with active_connections_lock:
            active_connections -= 1
            logging.info(f"Active connections: {active_connections}")

async def main():
    """
    Main function to run the SOCKS5 server.
    """
    logging.basicConfig(level=logging.INFO)
    try:
        server = await asyncio.start_server(
            handle_socks5, '172.20.10.1', 9876
        )
        addr = server.sockets[0].getsockname()
        logging.info("Serving on %s", addr)
        
        async with server:
            await server.serve_forever()
    except Exception as e:
        logging.error("Server failed: %s", e)

if __name__ == "__main__":
    asyncio.run(main())
