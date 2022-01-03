1. The procedures you used for generating your prime N and your primitive root g of N.
I generated my safe prime N using the miller rabin primailty test. To implement this algorithm, 
I referenced the following links:

 https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test#Complexity
 https://gist.github.com/Ayrx/5884790
 https://medium.com/@prudywsh/how-to-generate-big-prime-numbers-miller-rabin-49e6e6af32fb

Primitive root of g was implmented using slide 14 of More number theory, security of Diffie-Hellman slides.


2. A list of the files you have submitted that pertain to the problem, and a short description of
each file.
N/A


3. A list of what is implemented in the event that you are submitting a partial solution, or a
statement that the problem is solved in full.
Functions Implemented: 
	Networking Functions:
		create_socket()
		send()
		recieve()
	Low-level Functions:
		safe_prime()
		prim_root()
		calc_x()
		calc_u()
		calc_A()
		calc_B()
		calc_K_client()
		calc_K_server()
		calc_M1()
	High-level Functions:
		client_register()
		server_register()
		client_prepare()
		server_prepare()
4. A list of what is not implemented in the event that you are submitting a partial solution.
Functions NOT Implemented:
	Low-level Functions:
		find_Y()
	High-level Functions:
		client_protocol (not completed)
		server_protocol (not completed)

5. A list of known bugs, or a statement that there are no known bugs.
None known