#!/usr/bin/env python3
# IMPORTS

import argparse
from sys import exit
from threading import Thread
from time import sleep

# Callable works from here?
from typing import Any, Callable, Iterator, Mapping, Optional, Union

import socket
import random
import os
import hashlib
import time

# METHODS


def split_ip_port(string: str) -> Optional[tuple[str, int]]:
    """Split the given string into an IP address and port number.
    PARAMETERS
    ==========
    string: A string of the form IP:PORT.

    RETURNS
    =======
    If successful, a tuple of the form (IP,PORT), where IP is a
      string and PORT is a number. Otherwise, returns None.
    """

    assert type(string) == str

    try:
        idx = string.index(":")
        return (string[:idx], int(string[idx + 1 :]))
    except:
        return None


def int_to_bytes(value: int, length: int) -> bytes:
    """Convert the given integer into a bytes object with the specified
       number of bits. Uses network byte order.

    PARAMETERS
    ==========
    value: An int to be converted.
    length: The number of bytes this number occupies.

    RETURNS
    =======
    A bytes object representing the integer.
    """

    assert type(value) == int
    assert length > 0  # not necessary, but we're working with positive numbers only

    return value.to_bytes(length, "big")


def bytes_to_int(value: bytes) -> int:
    """Convert the given bytes object into an integer. Uses network
       byte order.

    PARAMETERS
    ==========
    value: An bytes object to be converted.

    RETURNS
    =======
    An integer representing the bytes object.
    """

    assert type(value) == bytes
    return int.from_bytes(value, "big")


def create_socket(ip: str, port: int, listen: bool = False) -> Optional[socket.socket]:
    """Create a TCP/IP socket at the specified port, and do the setup
       necessary to turn it into a connecting or receiving socket. Do
       not actually send or receive data here, and do not accept any
       incoming connections!

    PARAMETERS
    ==========
    ip: A string representing the IP address to connect/bind to.
    port: An integer representing the port to connect/bind to.
    listen: A boolean that flags whether or not to set the socket up
       for connecting or receiving.

    RETURNS
    =======
    If successful, a socket object that's been prepared according to
       the instructions. Otherwise, return None.
    """

    assert type(ip) == str
    assert type(port) == int

    if listen:
        try:
            sock = socket.socket()  # receiving
            sock.bind((ip, port))
            return sock
        except:
            return None
    else:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # connecting
            sock.connect((ip, port))
            return sock
        except:
            return None


def send(sock: socket.socket, data: bytes) -> int:
    """Send the provided data across the given socket. This is a
       'reliable' send, in the sense that the function retries sending
       until either a) all data has been sent, or b) the socket
       closes.

    PARAMETERS
    ==========
    sock: A socket object to use for sending and receiving.
    data: A bytes object containing the data to send.

    RETURNS
    =======
    The number of bytes sent. If this value is less than len(data),
       the socket is dead and a new one must be created, plus an unknown
       amount of the data was transmitted.
    """

    assert type(sock) == socket.socket
    assert type(data) == bytes

    try:
        buffer = sock.send(data)
        while buffer < len(data):
            remaining_data = data[:buffer] + data[len(data) :]
            buffer = sock.send(remaining_data)

        if sock.accept != 0:
            return buffer
        else:
            sock.close()
    except:
        return 0


def receive(sock: socket.socket, length: int) -> bytes:
    """Receive the provided data across the given socket. This is a
       'reliable' receive, in the sense that the function never returns
       until either a) the specified number of bytes was received, or b)
       the socket closes. Never returning is an option.

    PARAMETERS
    ==========
    sock: A socket object to use for sending and receiving.
    length: A positive integer representing the number of bytes to receive.

    RETURNS
    =======
    A bytes object containing the received data. If this value is less than
       length, the socket is dead and a new one must be created.
    """

    assert type(sock) == socket.socket
    assert length > 0

    try:
        buffer = sock.recv(length)
        bytes_received = len(buffer)

        if bytes_received < length:
            remaining_data = length - bytes_received
            buffer = buffer + (sock.recv(remaining_data))

        return buffer
    except:
        sock.close()
        return bytearray()


def is_prime(num: int):
    if num == 2 or num == 3:
        return True

    if num % 2 == 0:
        return False

    for n in range(3, int(pow(num, 1 / 2)) + 1, 2):
        if num % n == 0:
            return False
    return True


# referenced the following three links
# https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test#Complexity
# https://gist.github.com/Ayrx/5884790
# https://medium.com/@prudywsh/how-to-generate-big-prime-numbers-miller-rabin-49e6e6af32fb


def miller_rabin_primailty_test(n: int, k: int):
    if n == 2 or n == 3:
        return True

    if n <= 1 or n % 2 == 0:
        return False

    r = 0
    d = n - 1
    while d & 1 == 0:
        r += 1
        d //= 2

    for i in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue

        for j in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def find_prime(bits: int) -> int:
    random_int = 4

    while not miller_rabin_primailty_test(random_int, 40):
        random_int = random.getrandbits(bits - 1)
        random_int |= (1 << bits - 2) | 1  # mask MSB and LSB to 1
    return random_int


def safe_prime(bits: int = 512) -> int:
    """Generate a safe prime that is at least 'bits' bits long. The result
       should be greater than 1 << (bits-1).

    PARAMETERS
    ==========
    bits: An integer representing the number of bits in the safe prime.
       Must be greater than 1.

    RETURNS
    =======
    An integer matching the spec.
    """

    assert bits > 1

    q = find_prime(bits)
    N = (2 * q) + 1

    while not miller_rabin_primailty_test(N, 40):
        q = find_prime(bits)
        N = (2 * q) + 1

    return N


def prim_root(N: int) -> int:
    """Find a primitive root for N, a large safe prime. Hint: it isn't
       always 2.

    PARAMETERS
    ==========
    N: The prime in question. May be an integer or bytes object.

    RETURNS
    =======
    An integer representing the primitive root. Must be a positive
       number greater than 1.
    """
    # g is a primitive root of N iff g**((N-1) / 2) does not equal 1 (mod N) for every
    # prime factor q of N-1

    phi = N - 1
    q = phi // 2

    for g in range(2, phi):
        if pow(g, q, N) != 1:
            return g


def calc_x(s: bytes, pw: str) -> int:
    """Calculate the value of x, according to the assignment.

    PARAMETERS
    ==========
    s: The salt to use. A bytes object consisting of 16 bytes.
    pw: The password to use, as a string.

    RETURNS
    =======
    An integer representing x.
    """

    assert type(pw) == str
    assert type(s) == bytes

    password = bytes(pw, "utf-8")
    h = hashlib.blake2b(s + password, digest_size=32).digest()
    x = bytes_to_int(h)
    return x


def calc_A(g: Union[int, bytes], N: Union[int, bytes], a: Union[int, bytes]) -> int:
    """Calculate the value of A, according to the assignment.

    PARAMETERS
    ==========
    g: A primitive root of N. Could be an integer or bytes object.
    N: The safe prime. Could be an integer or bytes object.
    a: A random value between 0 and N-1, inclusive. Could be an integer or bytes object.

    RETURNS
    =======
    An integer representing A.
    """
    if isinstance(g, bytes):
        g = bytes_to_int(g)
    if isinstance(N, bytes):
        N = bytes_to_int(N)
    if isinstance(a, bytes):
        a = bytes_to_int(a)

    A = int(pow(g, a, N))
    return A


def calc_B(
    g: Union[int, bytes],
    N: Union[int, bytes],
    b: Union[int, bytes],
    k: Union[int, bytes],
    v: Union[int, bytes],
) -> int:
    """Calculate the value of B, according to the assignment.

    PARAMETERS
    ==========
    g: A primitive root of N. Could be an integer or bytes object.
    N: The safe prime. Could be an integer or bytes object.
    b: A random value between 0 and N-1, inclusive. Could be an integer or bytes object.
    k: The hash of N and g. Could be an integer or bytes object.
    v: See the assignment sheet. Could be an integer or bytes object.

    RETURNS
    =======
    An integer representing B.
    """
    if isinstance(g, bytes):
        g = bytes_to_int(g)
    if isinstance(N, bytes):
        N = bytes_to_int(N)
    if isinstance(b, bytes):
        b = bytes_to_int(b)
    if isinstance(k, bytes):
        k = bytes_to_int(k)
    if isinstance(v, bytes):
        v = bytes_to_int(v)

    B = (k * v + pow(g, b, N)) % N
    return B


def calc_u(A: Union[int, bytes], B: Union[int, bytes]) -> int:
    """Calculate the value of u, according to the assignment.

    PARAMETERS
    ==========
    A: See calc_A(). Could be an integer or bytes object.
    B: See calc_B(). Could be an integer or bytes object.

    RETURNS
    =======
    An integer representing u.
    """

    if isinstance(A, int):
        A = int_to_bytes(A, 64)
    if isinstance(B, int):
        B = int_to_bytes(B, 64)

    u = hashlib.blake2b(A + B, digest_size=32).digest()
    u = bytes_to_int(u)
    return u


def calc_K_client(
    N: Union[int, bytes],
    B: Union[int, bytes],
    k: Union[int, bytes],
    v: Union[int, bytes],
    a: Union[int, bytes],
    u: Union[int, bytes],
    x: Union[int, bytes],
) -> int:
    """Calculate the value of K_client, according to the assignment.

    PARAMETERS
    ==========
    N: The safe prime. Could be an integer or bytes object.
    B: See calc_B(). Could be an integer or bytes object.
    k: The hash of N and g. Could be an integer or bytes object.
    v: See the assignment sheet. Could be an integer or bytes object.
    a: A random value between 0 and N-1, inclusive. Could be an integer or bytes object.
    u: The hash of A and B. Could be an integer or bytes object.
    x: See calc_x(). Could be an integer or bytes object.

    RETURNS
    =======
    An integer representing K_client.
    """
    if isinstance(N, bytes):
        N = bytes_to_int(N)
    if isinstance(B, bytes):
        B = bytes_to_int(B)
    if isinstance(k, bytes):
        k = bytes_to_int(k)
    if isinstance(v, bytes):
        v = bytes_to_int(v)
    if isinstance(a, bytes):
        a = bytes_to_int(a)
    if isinstance(u, bytes):
        u = bytes_to_int(u)
    if isinstance(x, bytes):
        x = bytes_to_int(x)

    K_client = pow(B - (k * v), a + (u * x), N)
    return K_client


def calc_K_server(
    N: Union[int, bytes],
    A: Union[int, bytes],
    b: Union[int, bytes],
    v: Union[int, bytes],
    u: Union[int, bytes],
) -> int:
    """Calculate the value of K_server, according to the assignment.

    PARAMETERS
    ==========
    N: The safe prime. Could be an integer or bytes object.
    A: See calc_A(). Could be an integer or bytes object.
    b: A random value between 0 and N-1, inclusive. Could be an integer or bytes object.
    v: See the assignment sheet. Could be an integer or bytes object.
    u: The hash of A and B. Could be an integer or bytes object.

    RETURNS
    =======
    An integer representing K_server.
    """

    if isinstance(N, bytes):
        N = bytes_to_int(N)
    if isinstance(A, bytes):
        A = bytes_to_int(A)
    if isinstance(b, bytes):
        b = bytes_to_int(b)
    if isinstance(v, bytes):
        v = bytes_to_int(v)
    if isinstance(u, bytes):
        u = bytes_to_int(u)

    K_server = (pow(A, b, N) * pow(v, u * b, N)) % N
    return K_server


def find_Y(K_client: Union[int, bytes], bits: Union[int, bytes]) -> bytes:
    """Find a bytes object Y such that H(K_client+Y) starts with bits zero bits.
       See the assignment handout for how those bits should be arranged.

    PARAMETERS
    ==========
    K_client: See calc_K_client(). Could be an integer or bytes object.
    bits: The number of bits that must be zero. Could be an integer or bytes object.

    RETURNS
    =======
    A bytes object representing Y.
    """


def calc_M1(
    A: Union[int, bytes], K_server: Union[int, bytes], Y: Union[int, bytes]
) -> bytes:
    """Calculate the value of M1, according to the assignment.

    PARAMETERS
    ==========
    A: See calc_A(). Could be an integer or bytes object.
    K_server: See calc_K_server(). Could be an integer or bytes object.
    Y: See find_Y(). Could be an integer or bytes object.

    RETURNS
    =======
    A bytes object representing M2.
    """

    if isinstance(A, int):
        A = int_to_bytes(A, 64)
    if isinstance(K_server, int):
        K_server = int_to_bytes(K_server, 64)
    if isinstance(Y, int):
        Y = int_to_bytes(Y, 64)

    M1 = hashlib.blake2b(K_server + A + Y, digest_size=32).digest()
    return M1


def client_prepare() -> bytes:
    """Do the preparations necessary to connect to the server. Basically,
       just generate a salt.

    RETURNS
    =======
    A bytes object containing a randomly-generated salt, 16 bytes long.
    """
    salt = os.urandom(16)
    return salt


def server_prepare() -> tuple[int, int, int]:
    """Do the preparations necessary to accept clients. Generate N and g,
       and compute k.

    RETURNS
    =======
    A tuple of the form (g, N, k), containing those values as integers.
    """
    N = safe_prime()
    g = prim_root(N)

    N_bytes = int_to_bytes(N, 64)
    g_bytes = int_to_bytes(g, 64)

    k = hashlib.blake2b(g_bytes + N_bytes, digest_size=32).digest()
    k = bytes_to_int(k)

    return (g, N, k)


def client_register(
    ip: str, port: int, username: str, pw: str, s: bytes
) -> Optional[tuple[int, int, int]]:
    """Register the given username with the server, from the client.
       IMPORTANT: don't forget to send 'r'!

    PARAMETERS
    ==========
    ip: The IP address to connect to, as a string.
    port: The port to connect to, as an int.
    username: The username to register, as a string.
    pw: The password, as a string.
    s: The salt, a bytes object 16 bytes long.

    RETURNS
    =======
    If successful, return a tuple of the form (g, N, v), all integers.
       On failure, return None.
    """
    client = create_socket(ip, port)
    r = bytes(str("r"), "utf-8")
    send(client, r)

    g = receive(client, 64)
    N = receive(client, 64)

    if isinstance(g, bytes):
        g = bytes_to_int(g)
    if isinstance(N, bytes):
        N = bytes_to_int(N)

    x = calc_x(s, pw)
    v = int(pow(g, x, N))

    usrname = bytes(username, "utf-8")
    send(client, s)
    send(client, int_to_bytes(v, 64))
    send(client, int_to_bytes(len(usrname), 1))
    send(client, usrname)

    time_out = time.time() + 10

    while time.time() < time_out:
        try:
            client.connect(ip, port)
        except:
            return (g, N, v)

    client.close()
    return None


def server_register(
    sock: socket.socket, g: Union[int, bytes], N: Union[int, bytes], database: dict
) -> Optional[dict]:
    """Handle the server's side of the registration. IMPORTANT: reading the
       initial 'r' has been handled for you.

    PARAMETERS
    ==========
    sock: A socket object that contains the client connection.
    g: A primitive root of the safe prime. Could be an integer or bytes object.
    N: A safe prime. Could be an integer or bytes object.
    database: A dictionary of all registered users. The keys are usernames
       (as strings!), and the values are tuples of the form (s, v), where s
       is the salt (16 bytes) and v is as per the assignment (integer).

    RETURNS
    =======
    If the registration process was successful, return an updated version of the
       database. If it was not, return None. NOTE: a username that tries to
       re-register with a different salt and/or password is likely malicious,
       and should therefore count as an unsuccessful registration.
    """
    send(sock, int_to_bytes(g, 64))
    send(sock, int_to_bytes(N, 64))

    client_salt = receive(sock, 16)

    client_v = receive(sock, 64)
    client_v = bytes_to_int(client_v)

    usrname_len = receive(sock, 1)
    usrname_len = bytes_to_int(usrname_len)
    usrname = receive(sock, usrname_len)
    usrname = usrname.decode("utf-8")

    if usrname in database:
        s_v = database.get(usrname)
        if s_v[0] != client_salt or s_v[1] != client_v:
            time_out = time.time() + 10
            time.sleep(time_out)
            sock.close()
            return None
        else:
            sock.close()
            return database
    else:
        sock.close()
        database[usrname] = (client_salt, client_v)
        return database


def client_protocol(
    ip: str,
    port: int,
    g: Union[int, bytes],
    N: Union[int, bytes],
    username: str,
    pw: str,
    s: bytes,
) -> Optional[tuple[int, int]]:
    """Register the given username with the server, from the client.
       IMPORTANT: don't forget to send 'p'!

    PARAMETERS
    ==========
    ip: The IP address to connect to, as a string.
    port: The port to connect to, as an int.
    g: A primitive root of the safe prime. Could be an integer or bytes object.
    N: A safe prime. Could be an integer or bytes object.
    username: The username to register, as a string.
    pw: The password, as a string.
    s: The salt, a bytes object 16 bytes long. Must match what the server
       sends back.

    RETURNS
    =======
    If successful, return a tuple of the form (a, K_client), where both a and
       K_client are integers. If not, return None.
    """

    client = create_socket(ip, port)
    client.send(bytes(str("p"), "utf-8"))

    g_server = receive(client, 64)
    N_server = receive(client, 64)

    if type(g_server) is bytes:
        g_server = bytes_to_int(g_server)
    if type(N_server) is bytes:
        N_server = bytes_to_int(N_server)

    if type(g) is bytes:
        g = bytes_to_int(g)
    if type(N) is bytes:
        N = bytes_to_int(N)

    x = calc_x(s, pw)
    v = pow(g, x, N)

    if g == g_server and N == N_server:
        a = random.randrange(0, N - 1)
        A = calc_A(g, N, a)

        usrname = bytes(username, "utf-8")
        send(client, int_to_bytes(A, 64))
        send(client, int_to_bytes(len(usrname), 1))
        send(client, usrname)

        # server sends s and B where s is clients salt
        server_salt = receive(client, 16)
        B = receive(client, 64)

        if server_salt == s:
            u = calc_u(A, B)
            k = hashlib.blake2b(
                int_to_bytes(g, 64) + int_to_bytes(N, 64), digest_size=32
            ).digest()

            K_client = calc_K_client(N, B, k, v, a, u, x)
            bits = receive(client, 1)

            # Y = find_Y(K_client,bits)
            Y = b"\x03"  # hardcoded random byte value for testing
            send(client, Y)

            M1 = receive(client, 64)
            M1_K_client = int_to_bytes(K_client, 64)
            M1_A = int_to_bytes(A, 64)
            K_A_Y = bytes(M1_K_client + M1_A + Y)
            client_M1 = hashlib.blake2b(K_A_Y, digest_size=32).digest()

            if client_M1 == M1:
                return (a, K_client)

        client.close()
        return None


def server_protocol(
    sock: socket.socket,
    g: Union[int, bytes],
    N: Union[int, bytes],
    bits: int,
    database: dict,
) -> Optional[tuple[str, int, int]]:
    """Handle the server's side of the consensus protocal.
       IMPORTANT: reading the initial 'p' has been handled for
       you.

    PARAMETERS
    ==========
    sock: A socket object that contains the client connection.
    g: A primitive root of the safe prime. Could be an integer or bytes object.
    N: A safe prime. Could be an integer or bytes object.
    bits: The number of bits in H(K_server||Y) that must be zero. See the assignment
       handout for details.
    database: A dictionary of all registered users. The keys are usernames
       (as strings!), and the values are tuples of the form (s, v), where s
       is the salt (16 bytes) and v is as per the assignment (integer).

    RETURNS
    =======
    If successful, return a tuple of the form (username, b, K_server), where both b and
       K_server are integers while username is a string. If not, return None.
    """

    if isinstance(g, int):
        send_g = int_to_bytes(g, 64)
    if isinstance(N, int):
        send_N = int_to_bytes(N, 64)
    send(sock, send_g)
    send(sock, send_N)

    A = receive(sock, 64)
    usrname_len = receive(sock, 1)
    usrname_len = bytes_to_int(usrname_len)
    usrname = receive(sock, usrname_len)
    usrname = usrname.decode("utf-8")

    s_v = database.get(usrname)

    if s_v != None:

        k = hashlib.blake2b(send_g + send_N, digest_size=32).digest()
        k = bytes_to_int(k)

        # Server generates a random value b
        b = random.randrange(0, N - 1)
        B = calc_B(g, N, b, k, s_v[1])  # computes B

        send(sock, s_v[0])
        send(sock, int_to_bytes(B, 64))

        u = calc_u(A, B)  # computes u
        # Server computes Kserver
        K_server = calc_K_server(N, A, b, s_v[1], u)

        # The Server sends bits, a single byte representing a number.
        send_bits = int_to_bytes(bits, 1)
        send(sock, send_bits)  # Server sends bits
        Y = receive(sock, 64)

        K_server_Y = bytes_to_int(
            hashlib.blake2b(int_to_bytes(K_server, 64) + Y, digest_size=32).digest()
        )

        for i in range(0, bits + 1):
            if K_server_Y & i != 0:
                sock.close()
                return None

        M1 = calc_M1(A, K_server, Y)
        send(sock, M1)
        sock.close()
        return (usrname, b, K_server)
    sock.close()
    return None


# MAIN

if __name__ == "__main__":

    # parse the command line args
    cmdline = argparse.ArgumentParser(
        description="Test out a secure key exchange algorithm."
    )

    methods = cmdline.add_argument_group(
        "ACTIONS", "The three actions this program can do."
    )

    methods.add_argument(
        "--client",
        action="store_true",
        help="Perform registration and the protocol on the given IP address and port.",
    )
    methods.add_argument(
        "--server",
        action="store_true",
        help="Launch the server on the given IP address and port.",
    )
    methods.add_argument(
        "--quit",
        action="store_true",
        help="Tell the server on the given IP address and port to quit.",
    )

    methods = cmdline.add_argument_group(
        "OPTIONS", "Modify the defaults used for the above actions."
    )

    methods.add_argument(
        "--addr",
        metavar="IP:PORT",
        type=str,
        default="127.0.4.18:3180",
        help="The IP address and port to connect to.",
    )
    methods.add_argument(
        "--username",
        metavar="NAME",
        type=str,
        default="admin",
        help="The username the client sends to the server.",
    )
    methods.add_argument(
        "--password",
        metavar="PASSWORD",
        type=str,
        default="swordfish",
        help="The password the client sends to the server.",
    )
    methods.add_argument(
        "--salt",
        metavar="FILE",
        type=argparse.FileType("rb", 0),
        help="A specific salt for the client to use, stored as a file. Randomly generated if not given.",
    )
    methods.add_argument(
        "--timeout",
        metavar="SECONDS",
        type=int,
        default=600,
        help="How long until the program automatically quits. Negative or zero disables this.",
    )
    methods.add_argument(
        "--bits",
        type=int,
        default=20,
        help="The number of zero bits to challenge the Client to generate.",
    )
    methods.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Be more verbose about what is happening.",
    )

    args = cmdline.parse_args()

    # ensure the number of bits is sane
    if (args.bits < 1) or (args.bits > 64):
        args.bits = 20

    # handle the salt
    if args.salt:
        salt = args.salt.read(16)
    else:
        salt = client_prepare()

    if args.verbose:
        print(f"Program: Using salt <{salt.hex()}>")

    # first off, do we have a timeout?
    killer = None  # save this for later
    if args.timeout > 0:

        # define a handler
        def shutdown(time, verbose=False):

            sleep(time)
            if verbose:
                print("Program: exiting after timeout.", flush=True)

            return  # optional, but I like having an explicit return

        # launch it
        if args.verbose:
            print("Program: Launching background timeout.", flush=True)
        killer = Thread(target=shutdown, args=(args.timeout, args.verbose))
        killer.daemon = True
        killer.start()

    # next off, are we launching the server?
    result = None  # pre-declare this to allow for cascading

    server_proc = None
    if args.server:
        if args.verbose:
            print("Program: Attempting to launch server.", flush=True)
        result = split_ip_port(args.addr)

    if result is not None:

        IP, port = result
        if args.verbose:
            print(f"Server: Asked to start on IP {IP} and port {port}.", flush=True)
            print(f"Server: Generating N and g, this will take some time.", flush=True)

        g, N, k = server_prepare()

        if args.verbose:
            print(f"Server: Finished generating N and g.", flush=True)

        # use an inline routine as this doesn't have to be globally visible
        def server_loop(IP, port, g, N, k, bits, verbose=False):

            database = dict()  # for tracking registered users

            sock = create_socket(IP, port, listen=True)
            if sock is None:
                if verbose:
                    print(f"Server: Could not create socket, exiting.", flush=True)
                return

            if verbose:
                print(f"Server: Beginning connection loop.", flush=True)
            while True:

                (client, client_address) = sock.accept()
                if verbose:
                    print(f"Server: Got connection from {client_address}.", flush=True)

                mode = receive(client, 1)
                if len(mode) != 1:
                    if verbose:
                        print(
                            f"Server: Socket error with client, closing it and waiting for another connection.",
                            flush=True,
                        )
                    client.shutdown(socket.SHUT_RDWR)
                    client.close()
                    continue

                if mode == b"q":
                    if verbose:
                        print(
                            f"Server: Asked to quit by client. Shutting down.",
                            flush=True,
                        )
                    client.shutdown(socket.SHUT_RDWR)
                    client.close()
                    sock.shutdown(socket.SHUT_RDWR)
                    sock.close()
                    return

                elif mode == b"r":
                    if verbose:
                        print(f"Server: Asked to register by client.", flush=True)

                    temp = server_register(client, g, N, database)
                    if (temp is None) and verbose:
                        print(
                            f"Server: Registration failed, closing socket and waiting for another connection.",
                            flush=True,
                        )
                    elif temp is not None:
                        if verbose:
                            print(
                                f"Server: Registration complete, current users: {[x for x in temp]}.",
                                flush=True,
                            )
                        database = temp

                elif mode == b"p":
                    if verbose:
                        print(
                            f"Server: Asked to generate shared secret by client.",
                            flush=True,
                        )

                    temp = server_protocol(client, g, N, bits, database)
                    if (temp is None) and verbose:
                        print(
                            f"Server: Protocol failed, closing socket and waiting for another connection.",
                            flush=True,
                        )
                    elif type(temp) == tuple:
                        if verbose:
                            print(
                                f"Server: Protocol complete, negotiated shared key for {temp[0]}.",
                                flush=True,
                            )
                            print(f"Server:  Shared key is {temp[2]}.", flush=True)

                # clean up is done inside the functions
                # loop back

        # launch the server
        if args.verbose:
            print("Program: Launching server.", flush=True)
        server_proc = Thread(
            target=server_loop, args=(IP, port, g, N, k, args.bits, args.verbose)
        )
        server_proc.daemon = True
        server_proc.start()

    # finally, check if we're launching the client
    result = None  # clean this up

    client_proc = None
    if args.client:
        if args.verbose:
            print("Program: Attempting to launch client.", flush=True)
        result = split_ip_port(args.addr)

    if result is not None:

        IP, port = result
        if args.verbose:
            print(f"Client: Asked to connect to IP {IP} and port {port}.", flush=True)
        # another inline routine

        def client_routine(IP, port, username, pw, s, verbose=False):

            if verbose:
                print(f"Client: Beginning registration.", flush=True)

            results = client_register(IP, port, username, pw, s)
            if results is None:
                if verbose:
                    print(
                        f"Client: Registration failed, not attempting the protocol.",
                        flush=True,
                    )
                return
            else:
                g, N, v = results
                if verbose:
                    print(f"Client: Registration successful, g = {g}.", flush=True)

            if verbose:
                print(f"Client: Beginning the shared-key protocol.", flush=True)

            results = client_protocol(IP, port, g, N, username, pw, s)
            if results is None:
                if verbose:
                    print(f"Client: Protocol failed.", flush=True)
            else:
                a, K_client = results
                if verbose:
                    print(f"Client: Protocol successful.", flush=True)
                    print(f"Client:  K_client = {K_client}.", flush=True)

            return

        # launch the client
        if args.verbose:
            print("Program: Launching client.", flush=True)
        client_proc = Thread(
            target=client_routine,
            args=(IP, port, args.username, args.password, salt, args.verbose),
        )
        client_proc.daemon = True
        client_proc.start()

    # finally, the quitting routine
    result = None  # clean this up

    if args.quit:
        # defer on the killing portion, in case the client is active
        result = split_ip_port(args.addr)

    if result is not None:

        IP, port = result
        if args.verbose:
            print(f"Quit: Asked to connect to IP {IP} and port {port}.", flush=True)
        if client_proc is not None:
            if args.verbose:
                print(f"Quit: Waiting for the client to complete first.", flush=True)
            client_proc.join()

        if args.verbose:
            print("Quit: Attempting to kill the server.", flush=True)

        # no need for threading here
        sock = create_socket(IP, port)
        if sock is None:
            if args.verbose:
                print(
                    f"Quit: Could not connect to the server to send the kill signal.",
                    flush=True,
                )
        else:
            count = send(sock, b"q")
            if count != 1:
                if args.verbose:
                    print(f"Quit: Socket error when sending the signal.", flush=True)
            elif args.verbose:
                print(f"Quit: Signal sent successfully.", flush=True)

            sock.shutdown(socket.SHUT_RDWR)
            sock.close()

    # finally, we wait until we're told to kill ourselves off, or both the client and server are done
    while not ((server_proc is None) and (client_proc is None)):

        if not killer.is_alive():
            if args.verbose:
                print(f"Program: Timeout reached, so exiting.", flush=True)
            if client_proc is not None:
                client_proc.terminate()
            if server_proc is not None:
                server_proc.terminate()
            exit()

        if (client_proc is not None) and (not client_proc.is_alive()):
            if args.verbose:
                print(f"Program: Client terminated.", flush=True)
            client_proc = None

        if (server_proc is not None) and (not server_proc.is_alive()):
            if args.verbose:
                print(f"Program: Server terminated.", flush=True)
            server_proc = None
