from tkinter import *
from tkinter import messagebox
import socket
from threading import Thread

hostname = socket.gethostname()
ip = socket.gethostbyname(hostname)
BUFSIZ = 1024
client_socket = None
receive_thread = None
message = None


# Disconnect From the server
def Disconnect():
    if (client_socket):
        client_socket.close()
    ConnectButton.configure(text="Connect", command=Connect)
    sendButton.configure(state="disabled")
    uname.configure(state="normal")
    upass.configure(state="normal")


# Connect to Remote
def Connect():
    global client_socket
    global receive_thread

    try:
        # Assign resusable socket
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        ADDR = (remote_ip.get(), int(remote_port.get()))
        print("Server Address: ", ADDR)
        # Attempt connection to server
        client_socket.connect(ADDR)
        receive_thread = Thread(target=RecvMessage)
        receive_thread.start()
        SendLogin()
        # Change Buttons and entry states
        ConnectButton.configure(text="Disconnect", command=Disconnect)
        sendButton.configure(state="normal")
        uname.configure(state="disabled")
        upass.configure(state="disabled")
        # Announce to server that you have joined
        client_socket.sendall((uname.get() + " has joined the server").encode('utf-8'))
    except OSError as ex:  # Server Declines Connection
        # print("Error: ",ex)
        print("Connection to Server failed")
    except ValueError:
        print("Port should be a valid number")


# Receive Function
def RecvMessage():
    # loop that waits for messages
    while True:
        try:
            msg = client_socket.recv(BUFSIZ).decode("utf8")
            if msg == 'Incorrect login/password':
                msg_list.insert(END, 'Incorrect login or password, or user with that username already exist')
                Disconnect()
                break
            else:
                msg_list.insert(END, msg)
        except OSError:  # Possibly client has left the chat.
            print("You have been disconnected from the server")
            Disconnect()
            break


# Send Function
def SendMessage():
    msg = message.get("1.0", END)  # Retrives data from input field.
    message.delete("1.0", END)  # Clears input field.
    client_socket.send(bytes(uname.get() + ": " + msg, "utf8"))  # Send message

def SendLogin():
    client_socket.send(bytes("^7*@"+uname.get() + "@" + upass.get(), "utf8"))  # Send message


# Function called on exit to terminate running threads and close sockets
def on_closing():
    if messagebox.askokcancel("Quit", "Do you want to quit?"):
        if (client_socket):
            client_socket.close()
        if (receive_thread and receive_thread.is_alive()):
            receive_thread.join()
        mainWindow.destroy()


# GUI
mainWindow = Tk()
mainWindow.title('Chat Application - Client')

configFrame = Frame(mainWindow)
# Set IP and Port along with username
Label(configFrame, text='IP Address').grid(row=0, column=0)

Label(configFrame, text='Name').grid(row=0, column=2)
uname = Entry(configFrame, state="normal")
uname.grid(row=0, column=3)
uname.insert(END, "User")
Label(configFrame, text='Name').grid(row=0, column=2)

Label(configFrame, text='Password').grid(row=1, column=2)
upass = Entry(configFrame, state="normal")
upass.grid(row=1, column=3)
upass.insert(END, "Pass")

Label(configFrame, text='Port').grid(row=1)
remote_ip = Entry(configFrame)
remote_ip.insert(END, '127.0.0.1')
remote_ip.grid(row=0, column=1)
remote_port = Entry(configFrame)
remote_port.insert(END, '8008')
remote_port.grid(row=1, column=1)

ConnectButton = Button(configFrame, text='Connect', width=25, command=Connect)
ConnectButton.grid(row=3, column=2)

# Show Current IP and Hostname
Label(configFrame, text="My IP: ").grid(row=2, column=0)
Label(configFrame, text=ip).grid(row=2, column=1)
Label(configFrame, text="My Hostname: ").grid(row=3, column=0)
Label(configFrame, text=hostname).grid(row=3, column=1)

configFrame.grid(row=0)

# Message Receive Box
messagesFrame = Frame(mainWindow)
scrollbar = Scrollbar(messagesFrame)  # To navigate through previous messages.
# Following will contain the messages.
msg_list = Listbox(messagesFrame, height=15, width=50, bg="silver", yscrollcommand=scrollbar.set)
msg_list.insert(0, "- - - - - - Beginning of Chat - - - - - - -")
scrollbar.pack(side=RIGHT, fill=Y)
msg_list.pack(side=LEFT, fill=BOTH)
msg_list.pack()
messagesFrame.grid(row=4)

# Send Message Box
SendFrame = Frame(mainWindow)
message = Text(SendFrame, height=4)
message.grid(row=6, column=0)
sendButton = Button(SendFrame, text='Send Message', width=20, command=SendMessage, state='disabled')
sendButton.grid(row=6, column=1)
SendFrame.grid(row=5)

mainWindow.protocol("WM_DELETE_WINDOW", on_closing)
mainWindow.mainloop()