#!/usr/bin/env python3

##### IMPORTS

import argparse
from sys import exit
from threading import Thread
from time import sleep
from typing import Any, Callable, Iterator, Mapping, Optional, Union # Callable works from here?

# Insert your imports here

##### METHODS

def split_ip_port( string:str ) -> Optional[tuple[str,int]]:
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
        idx = string.index(':')
        return (string[:idx], int(string[idx+1:]))
    except:
        return None

def int_to_bytes( value:int, length:int ) -> bytes:
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
    assert length > 0   # not necessary, but we're working with positive numbers only

    return value.to_bytes( length, 'big' )


def bytes_to_int( value:bytes ) -> int:
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
    return int.from_bytes( value, 'big' )


def create_socket( ip:str, port:int, listen:bool=False ) -> Optional[socket.socket]:
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

    # delete this comment and insert your code here

def send( sock:socket.socket, data:bytes ) -> int:
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

    # delete this comment and insert your code here

def receive( sock:socket.socket, length:int ) -> bytes:
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

    # delete this comment and insert your code here

def safe_prime( bits:int=512 ) -> int:
    """Generate a safe prime that is at least 'bits' bits long. The result
       should be greater than 1 << (bits-1).

    PARAMETERS
    ==========
    bits: An integer representing the number of bits in the safe prime.
       Must be greater than 1.

    RETURNS
    =======
    An interger matching the spec.
    """

    assert bits > 1

    # delete this comment and insert your code here

def prim_root( N:int ) -> int:
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

    # delete this comment and insert your code here


def calc_x( s:bytes, pw:str ) -> int:
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

    # delete this comment and insert your code here

def calc_A( g:Union[int,bytes], N:Union[int,bytes], a:Union[int,bytes] ) -> int:
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

    # delete this comment and insert your code here

def calc_B( g:Union[int,bytes], N:Union[int,bytes], b:Union[int,bytes], \
        k:Union[int,bytes], v:Union[int,bytes] ) -> int:
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

    # delete this comment and insert your code here

def calc_u( A:Union[int,bytes], B:Union[int,bytes] ) -> int:
    """Calculate the value of u, according to the assignment.

    PARAMETERS
    ==========
    A: See calc_A(). Could be an integer or bytes object.
    B: See calc_B(). Could be an integer or bytes object.

    RETURNS
    =======
    An integer representing u.
    """

    # delete this comment and insert your code here

def calc_K_client( N:Union[int,bytes], B:Union[int,bytes], \
        k:Union[int,bytes], v:Union[int,bytes], a:Union[int,bytes], \
        u:Union[int,bytes], x:Union[int,bytes] ) -> int:
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

    # delete this comment and insert your code here

def calc_K_server( N:Union[int,bytes], A:Union[int,bytes], \
        b:Union[int,bytes], v:Union[int,bytes], u:Union[int,bytes] ) -> int:
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

    # delete this comment and insert your code here

def find_Y( K_client:Union[int,bytes], bits:Union[int,bytes] ) -> bytes:
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

    # delete this comment and insert your code here

def calc_M1( A:Union[int,bytes], K_server:Union[int,bytes], Y:Union[int,bytes] ) -> bytes:
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

    # delete this comment and insert your code here

def client_prepare() -> bytes:
    """Do the preparations necessary to connect to the server. Basically,
       just generate a salt.

    RETURNS
    =======
    A bytes object containing a randomly-generated salt, 16 bytes long.
    """

    # delete this comment and insert your code here

def server_prepare() -> tuple[int,int,int]:
    """Do the preparations necessary to accept clients. Generate N and g,
       and compute k.

    RETURNS
    =======
    A tuple of the form (g, N, k), containing those values as integers.
    """

    # delete this comment and insert your code here

def client_register( ip:str, port:int, username:str, pw:str, s:bytes ) -> \
        Optional[tuple[int,int,int]]:
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

    # delete this comment and insert your code here

def server_register( sock:socket.socket, g:Union[int,bytes], N:Union[int,bytes], \
        database:dict ) -> Optional[dict]:
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

    # delete this comment and insert your code here

def client_protocol( ip:str, port:int, g:Union[int,bytes], N:Union[int,bytes], \
        username:str, pw:str, s:bytes ) -> Optional[tuple[int,int]]:
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

    # delete this comment and insert your code here

def server_protocol( sock:socket.socket, g:Union[int,bytes], N:Union[int,bytes], \
        bits:int, database:dict ) -> Optional[tuple[str,int,int]]:
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

    # delete this comment and insert your code here


##### MAIN

if __name__ == '__main__':

    # parse the command line args
    cmdline = argparse.ArgumentParser( description="Test out a secure key exchange algorithm." )

    methods = cmdline.add_argument_group( 'ACTIONS', "The three actions this program can do." )

    methods.add_argument( '--client', action='store_true', \
        help='Perform registration and the protocol on the given IP address and port.' )
    methods.add_argument( '--server', action='store_true', \
        help='Launch the server on the given IP address and port.' )
    methods.add_argument( '--quit', action='store_true', \
        help='Tell the server on the given IP address and port to quit.' )

    methods = cmdline.add_argument_group( 'OPTIONS', "Modify the defaults used for the above actions." )

    methods.add_argument( '--addr', metavar='IP:PORT', type=str, default="127.0.4.18:3180", \
        help='The IP address and port to connect to.' )
    methods.add_argument( '--username', metavar='NAME', type=str, default="admin", \
        help='The username the client sends to the server.' )
    methods.add_argument( '--password', metavar='PASSWORD', type=str, default="swordfish", \
        help='The password the client sends to the server.' )
    methods.add_argument( '--salt', metavar='FILE', type=argparse.FileType('rb', 0), \
        help='A specific salt for the client to use, stored as a file. Randomly generated if not given.' )
    methods.add_argument( '--timeout', metavar='SECONDS', type=int, default=600, \
        help='How long until the program automatically quits. Negative or zero disables this.' )
    methods.add_argument( '--bits', type=int, default=20, \
        help='The number of zero bits to challenge the Client to generate.' )
    methods.add_argument( '-v', '--verbose', action='store_true', \
        help="Be more verbose about what is happening." )

    args = cmdline.parse_args()

    # ensure the number of bits is sane
    if (args.bits < 1) or (args.bits > 64):
        args.bits = 20

    # handle the salt
    if args.salt:
        salt = args.salt.read( 16 )
    else:
        salt = client_prepare()

    if args.verbose:
        print( f"Program: Using salt <{salt.hex()}>" )
    
    # first off, do we have a timeout?
    killer = None           # save this for later
    if args.timeout > 0:

        # define a handler
        def shutdown( time, verbose=False ):

            sleep( time )
            if verbose:
                print( "Program: exiting after timeout.", flush=True )

            return # optional, but I like having an explicit return

        # launch it
        if args.verbose:
            print( "Program: Launching background timeout.", flush=True )
        killer = Thread( target=shutdown, args=(args.timeout,args.verbose) )
        killer.daemon = True
        killer.start()

    # next off, are we launching the server?
    result      = None     # pre-declare this to allow for cascading

    server_proc = None
    if args.server:
        if args.verbose:
            print( "Program: Attempting to launch server.", flush=True )
        result = split_ip_port( args.addr )

    if result is not None:

        IP, port = result
        if args.verbose:
            print( f"Server: Asked to start on IP {IP} and port {port}.", flush=True )
            print( f"Server: Generating N and g, this will take some time.", flush=True )
        g, N, k = server_prepare() 
        if args.verbose:
            print( f"Server: Finished generating N and g.", flush=True )

        # use an inline routine as this doesn't have to be globally visible
        def server_loop( IP, port, g, N, k, bits, verbose=False ):
            
            database = dict()           # for tracking registered users

            sock = create_socket( IP, port, listen=True )
            if sock is None:
                if verbose:
                    print( f"Server: Could not create socket, exiting.", flush=True )
                return

            if verbose:
                print( f"Server: Beginning connection loop.", flush=True )
            while True:

                (client, client_address) = sock.accept()
                if verbose:
                    print( f"Server: Got connection from {client_address}.", flush=True )

                mode = receive( client, 1 )
                if len(mode) != 1:
                    if verbose:
                        print( f"Server: Socket error with client, closing it and waiting for another connection.", flush=True )
                    client.shutdown(socket.SHUT_RDWR)
                    client.close()
                    continue

                if mode == b'q':
                    if verbose:
                        print( f"Server: Asked to quit by client. Shutting down.", flush=True )
                    client.shutdown(socket.SHUT_RDWR)
                    client.close()
                    sock.shutdown(socket.SHUT_RDWR)
                    sock.close()
                    return

                elif mode == b'r':
                    if verbose:
                        print( f"Server: Asked to register by client.", flush=True )

                    temp = server_register( client, g, N, database )
                    if (temp is None) and verbose:
                            print( f"Server: Registration failed, closing socket and waiting for another connection.", flush=True )
                    elif temp is not None:
                        if verbose:
                            print( f"Server: Registration complete, current users: {[x for x in temp]}.", flush=True )
                        database = temp

                elif mode == b'p':
                    if verbose:
                        print( f"Server: Asked to generate shared secret by client.", flush=True )

                    temp = server_protocol( client, g, N, bits, database )
                    if (temp is None) and verbose:
                            print( f"Server: Protocol failed, closing socket and waiting for another connection.", flush=True )
                    elif type(temp) == tuple:
                        if verbose:
                            print( f"Server: Protocol complete, negotiated shared key for {temp[0]}.", flush=True )
                            print( f"Server:  Shared key is {temp[2]}.", flush=True )

                # clean up is done inside the functions
                # loop back

        # launch the server
        if args.verbose:
            print( "Program: Launching server.", flush=True )
        server_proc = Thread( target=server_loop, args=(IP, port, g, N, k, args.bits, args.verbose) )
        server_proc.daemon = True
        server_proc.start()

    # finally, check if we're launching the client
    result      = None     # clean this up

    client_proc = None
    if args.client:
        if args.verbose:
            print( "Program: Attempting to launch client.", flush=True )
        result = split_ip_port( args.addr )

    if result is not None:

        IP, port = result
        if args.verbose:
            print( f"Client: Asked to connect to IP {IP} and port {port}.", flush=True )
        # another inline routine
        def client_routine( IP, port, username, pw, s, verbose=False ):

            if verbose:
                print( f"Client: Beginning registration.", flush=True )

            results = client_register( IP, port, username, pw, s )
            if results is None:
                if verbose:
                    print( f"Client: Registration failed, not attempting the protocol.", flush=True )
                return
            else:
                g, N, v = results
                if verbose:
                    print( f"Client: Registration successful, g = {g}.", flush=True )

            if verbose:
                print( f"Client: Beginning the shared-key protocol.", flush=True )

            results = client_protocol( IP, port, g, N, username, pw, s )
            if results is None:
                if verbose:
                    print( f"Client: Protocol failed.", flush=True )
            else:
                a, K_client = results
                if verbose:
                    print( f"Client: Protocol successful.", flush=True )
                    print( f"Client:  K_client = {K_client}.", flush=True )

            return

        # launch the client
        if args.verbose:
            print( "Program: Launching client.", flush=True )
        client_proc = Thread( target=client_routine, args=(IP, port, args.username, args.password, salt, args.verbose) )
        client_proc.daemon = True
        client_proc.start()

    # finally, the quitting routine
    result      = None     # clean this up

    if args.quit:
        # defer on the killing portion, in case the client is active
        result = split_ip_port( args.addr )

    if result is not None:

        IP, port = result
        if args.verbose:
            print( f"Quit: Asked to connect to IP {IP} and port {port}.", flush=True )
        if client_proc is not None:
            if args.verbose:
                print( f"Quit: Waiting for the client to complete first.", flush=True )
            client_proc.join()

        if args.verbose:
            print( "Quit: Attempting to kill the server.", flush=True )

        # no need for threading here
        sock = create_socket( IP, port )
        if sock is None:
            if args.verbose:
                print( f"Quit: Could not connect to the server to send the kill signal.", flush=True )
        else:
            count = send( sock, b'q' )
            if count != 1:
                if args.verbose:
                    print( f"Quit: Socket error when sending the signal.", flush=True )
            elif args.verbose:
                    print( f"Quit: Signal sent successfully.", flush=True )

            sock.shutdown(socket.SHUT_RDWR)
            sock.close()

    # finally, we wait until we're told to kill ourselves off, or both the client and server are done
    while not ((server_proc is None) and (client_proc is None)):

        if not killer.is_alive():
            if args.verbose:
                print( f"Program: Timeout reached, so exiting.", flush=True )
            if client_proc is not None:
                client_proc.terminate()
            if server_proc is not None:
                server_proc.terminate()
            exit()

        if (client_proc is not None) and (not client_proc.is_alive()):
            if args.verbose:
                print( f"Program: Client terminated.", flush=True )
            client_proc = None
        
        if (server_proc is not None) and (not server_proc.is_alive()):
            if args.verbose:
                print( f"Program: Server terminated.", flush=True )
            server_proc = None
