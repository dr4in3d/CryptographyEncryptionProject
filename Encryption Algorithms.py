from math import *
import random
from bitarray import bitarray

# Menu to select the different algorithms and options
def menu(first_input):
    list = input("1. Generate Key  \n"
                  "2. Encrypt Message \n"
                  "3. Decrypt Message \n"
                  "4. Intercept Message \n"
                  "Enter Option:")

    if first_input == '1':
        if list == '1':
            print("El Gamal Key Gen")
            elgamal_keygen()

        elif list == '2':
            print("El Gamal Encrypt")
            elgamal_encrypt()
        elif list == '3':
            print("El Gamal Decrypt")
            elgamal_decrypt()
        elif list == '4':
            print("El Gamal Crack")
            elgamal_crack()
        else:
            print("Invalid Input")
    elif first_input == '2':
        if list == '1':
            print("RSA Key Gen")
            rsa_keygen()
        elif list == '2':
            print("RSA Encrypt")
            rsa_encrypt()
        elif list == '3':
            print("RSA Decrypt")
            rsa_decrypt()
        elif list == '4':
            print("RSA Crack")
            rsa_crack()
    else:
        print("Invalid Input")

# fast exponentiation
def fast_exp(x, e, m):
    y = 1
    while e > 0:

        if e % 2 == 0:
            x = x * x % m
            e = e // 2
        else:
           e = e - 1
           y = y * x % m

    return y

# Testing if value is a prime
def primetest(n):

    k = 20  # number of rounds

    # if n is even return False
    if n <= 1:
        return False
    # handle base cases
    if n <= 3:
        return True

    d = n - 1

    # divide n - 1 by 2 until some odd number m
    while d % 2 == 0:
        d //= 2

    # Iterate given number 'k' times
    for i in range(k):
        if millerrabin(d, n) is False:
            return False

    return True

# Euclidean algorithm
def gcd(a, b):
    if a == 0:
        return b

    return gcd(b % a, a)

# Extended Euclidean
def extendedeuclid(a, b):
    if a == 0:
        return b, 0, 1
    else:
        gcd, x, y = extendedeuclid(b % a, a)
        return (gcd, (y - (b//a) * x), x)

def millerrabin(m, n):
    # Generate a random number
    # Corner case to ensure that n > 4
    b = 2 + random.randint(1, n - 4)

    # Compute b^m % n
    x = fast_exp(b, m, n)

    # if b is congruent to 1 % n (which = 1)
    if x == 1 or x == n - 1:
        return True

    # start squaring from previous result (x is your new b)
    while m != n - 1:

        # compute x^2 % n
        x = fast_exp(x, 2, n)
        m *= 2
        # if x is congruent to 1 % n (which = 1) then n is composite
        if x == 1:
            return False
        # if x == n - 1 then n is prime w/ probability > 3/4
        if x == n - 1:
            return True

    # n is composite
    return False

# Multiplicative inverse
def multInverse(v, m):
    v = v % m
    for x in range(1, m):
        if (v * x) % m == 1:
            return x
    return 1

# Baby step Giant Step
def babystepgiantstep(p, g, a):

    # Find the ceiling of square root p - 1
    n = ceil(sqrt(p - 1))
    N = int(n)

    # create a dictionary for baby step
    d = {(g ** i % p): i for i in range(N)}
    # find the multiplicative inverse g^-1
    g_inv = multInverse(g, p)
    # compute c = (g^-1)^m
    c = fast_exp(g_inv, N, p)
    # Giant step
    for j in range(N):
        y = (a * (c ** j % p) % p)

        if y in d:
            return (j * N + d[y]) % p

    return None

#Blum Blum Shub

def blumblum(bits):
    # Generate a random p and q
    p = random.randint(1, 2 ** bits)
    q = random.randint(1, 2 ** bits)

    # Calculate n by multiplying p and q
    n = p * q

    # Create a seed and randomly pick a seed in range 1 through p
    seed = bits * [0]
    seed[0] = random.randint(1, p)

    # Calculate s1 through si with the chosen seed
    for i in range(1, len(seed)):
        seed[i] = ((seed[i - 1] ** 2) % n)

    # Create an array of 16 bits and use the seeds (s1 through si) to extract the bits

    bit = bitarray(bits)
    # initialize all the bits to 0
    bit.setall(0)

    # Loop through the array of seeds and mod each seed by 2
    for i in range(bits):
        bit[i] = seed[i] % 2

    # set result to 0
    res = 0

    # store the integer result from the bits in the bit array
    for value in bit:
        res = res << 1 | value
    return res



# Pollard Rho
def pollardrho(n):
    # test to make sure n is prime
    if primetest(n) is False:
        primetest(n)

    # initialize x and y
    x = 2
    y = (x ** 2 + 1) % n
    while True:
        g = gcd((x - y) % n, n)
        if 1 < g < n:
            return g

        elif g == 1:
            x = (x ** 2 + random.randint(2, n - 1)) % n
            y = ((y ** 2 + random.randint(2, n - 1)) ** 2 + random.randint(2, n - 1)) % n
            continue

        elif g == n:
            pollardrho(n)
            break


# El Gamal Key generation
def elgamal_keygen():
    while True:
        # Generate a random prime p.
        p = blumblum(16)
        # Test the p and if it's prime generate a new p
        while primetest(p) is not True:
            p = blumblum(16)
        # calculate q because we need a Sofie Germain Prime
        q = (p - 1) // 2
        # Test the q and see if it's prime. If it's not true generate a new q
        if primetest(q) is False:
            continue
        # If q is prime
        elif primetest(q) is True:
            # generate a random g in range 1 and p and test it for g^2 % p and g^q % p. Has to pass both tests
            g = random.randint(1, p)
            # g^2 % p and if it == 1 then it fails, so we need to generate another g
            while (g ** 2) % p == 1:
                g = random.randint(1, p)
            # g^q % p and if it == 1 then it fails, so we need to generate another g
            while (g ** q) % p == 1:
                g = random.randint(1, p)
        r = random.randint(1, p)
        gr = fast_exp(g, r, p)
        print("prime:", p, "generator:", g, "r:", r, "g^r:", gr)
        break

# El Gamal Encryption
def elgamal_encrypt():
    # inputs for p, g, gr, and l
    while True:
        try:
            p = int(input("Please enter the prime value:"))

        except ValueError:
            print("Invalid input, please enter a valid integer value.")
            continue
        else:
            # successful value entered
            break

    while True:
        try:
            g = int(input("Please enter a generator key:"))

        except ValueError:
            print("Invalid input, please enter a valid integer value.")
            continue
        else:
            # successful value entered
            break

    while True:
        try:
            gr = int(input("Please enter a g^r value:"))

        except ValueError:
            print("Invalid input, please enter a valid integer value.")
            continue
        else:
            # successful value entered
            break
    while True:
        try:
            l = int(input("Please enter a 'secret' key:"))

        except ValueError:
            print("Invalid input, please enter a valid integer value.")
            continue
        else:
            # successful value entered
            break
    # Calculate g^lr and g^l
    glr = fast_exp(gr, l, p)
    gl = fast_exp(g, l, p)

    # input message you want to send
    while True:
        try:
            msg = int(input("Please enter a message:"))

        except ValueError:
            print("Invalid input, please enter a valid integer value.")
            continue
        else:
            # successful value entered
            break
    # perform the calculations for the ciphertext and print it
    encryptmsg = (msg * glr) % p
    print("Ciphertext:", encryptmsg, "g^l is:", gl)

# El Gamal Decryption
def elgamal_decrypt():
    # input p, ciphertext, g^l, and r
    while True:
        try:
            p = int(input("Please enter prime value:"))

        except ValueError:
            print("Invalid input, please enter a valid integer value.")
            continue
        else:
            # successful value entered
            break
    while True:
        try:
            encryptmsg = int(input("Please enter a ciphertext:"))

        except ValueError:
            print("Invalid input, please enter a valid integer value.")
            continue
        else:
            # successful value entered
            break
    while True:
        try:
            gl = int(input("Please enter a g^l key:"))

        except ValueError:
            print("Invalid input, please enter a valid integer value.")
            continue
        else:
            # successful value entered
            break

    while True:
        try:
            r = int(input("Please enter a r key:"))

        except ValueError:
            print("Invalid input, please enter a valid integer value.")
            continue
        else:
            # successful value entered
            break

    # calculate g^lr and inverse of g^lr
    glr = fast_exp(gl, r, p)
    inverse = multInverse(glr, p)
    # the inverse * glr % p should give you the clear text
    cleartext = inverse * encryptmsg % p

    print("The original message is:", cleartext)

# Breaking El Gamal Encryption
def elgamal_crack():
    while True:
        try:
            p = int(input("Please enter intercepted prime value:"))

        except ValueError:
            print("Invalid input, please enter a valid integer value.")
            continue
        else:
            # successful value entered
            break
    while True:
        try:
            g = int(input("Please enter intercepted generator value:"))

        except ValueError:
            print("Invalid input, please enter a valid integer value.")
            continue
        else:
            # successful value entered
            break

    while True:
        try:
            gr = int(input("Please enter intercepted g^r value:"))

        except ValueError:
            print("Invalid input, please enter a valid integer value.")
            continue
        else:
            # successful value entered
            break

    while True:
        try:
            gl = int(input("Please enter intercepted g^l value:"))

        except ValueError:
            print("Invalid input, please enter a valid integer value.")
            continue
        else:
            # successful value entered
            break

    while True:
        try:
            encryptmsg = int(input("Please enter intercepted ciphertext:"))

        except ValueError:
            print("Invalid input, please enter a valid integer value.")
            continue
        else:
            # successful value entered
            break
    # use Baby Step Giant Step to find r and l
    r = babystepgiantstep(p, g, gr)
    print("r is:", r)
    l = babystepgiantstep(p, g, gl)
    print("l is:", l)
    # find g^l and g^lr
    gl = fast_exp(g, l, p)
    glr = fast_exp(gl, r, p)
    # find the inverse of g^lr
    inverse = multInverse(glr, p)
    # by multiplying the ciphertext and inverse you can find the clear text
    cleartext = inverse * encryptmsg % p

    print("This is the original message:", cleartext)

# RSA Key Generation
def rsa_keygen():
    print("Generating Keys")
    while True:
        # Generate a random prime p
        p = blumblum(16)
        # Test the p and if it's prime generate a new p
        while primetest(p) is not True:
            p = blumblum(16)
        # Generate a random prime q
        q = blumblum(16)
        # Test the q and if it's prime generate a new q
        while primetest(q) is not True:
            q = blumblum(16)

        # Calculate n by multiplying p and q
        n = p * q
        # Calculate phi(n)
        phi_n = (p - 1) * (q - 1)

        # Generate e such that it is in Z^x phi(n)
        e = random.randint(1, phi_n)

        # Test e using euclidean algorithm and make sure it is in Z^x phi(n)
        while gcd(e, phi_n) != 1:
            e = random.randint(1, phi_n)

        # calculate d which is the inverse of e in Z^x phi(n)

        d = multInverse(e, phi_n)

        print("n is:", n, "e is:", e, "d is:", d)

        break

# RSA encryption
def rsa_encrypt():
    # input the message, e, and n
    while True:
        try:
            msg = int(input("Please enter a message:"))

        except ValueError:
            print("Invalid input, please enter a valid integer value.")
            continue
        else:
            # successful value entered
            break
    while True:
        try:
            e = int(input("Please enter e:"))

        except ValueError:
            print("Invalid input, please enter a valid integer value.")
            continue
        else:
            # successful value entered
            break
    while True:
        try:
            n = int(input("Please enter n:"))

        except ValueError:
            print("Invalid input, please enter a valid integer value.")
            continue
        else:
            # successful value entered
            break

    # to encrypt the message  -> message^e % n
    # we will use fast exponentiation because these values can get very large
    encryptmsg = fast_exp(msg, e, n)
    print("The ciphertext is:", encryptmsg)

# RSA decryption
def rsa_decrypt():
    # input the ciphertext, d, and n
    while True:
        try:
            encryptmsg = int(input("Please enter a ciphertext:"))

        except ValueError:
            print("Invalid input, please enter a valid integer value.")
            continue
        else:
            # successful value entered
            break
    while True:
        try:
            d = int(input("Please enter d:"))

        except ValueError:
            print("Invalid input, please enter a valid integer value.")
            continue
        else:
            # successful value entered
            break

    while True:
        try:
            n = int(input("Please enter n:"))

        except ValueError:
            print("Invalid input, please enter a valid integer value.")
            continue
        else:
            # successful value entered
            break
    # to decrypt the message  -> ciphertext^d % n
    # we will use fast exponentiation because these values can get very large
    cleartext = fast_exp(encryptmsg, d, n)
    print("The original message is", cleartext)

# Breaking RSA
def rsa_crack():
    # input n, e, and ciphertext
    while True:
        try:
            n = int(input("Please enter n:"))

        except ValueError:
            print("Invalid input, please enter a valid integer value.")
            continue
        else:
            # successful value entered
            break

    f1 = pollardrho(n)
    print("First Factor is:", f1)
    while True:
        try:
            e = int(input("Please enter e:"))

        except ValueError:
            print("Invalid input, please enter a valid integer value.")
            continue
        else:
            # successful value entered
            break
    while True:
        try:
            encryptmsg = int(input("Please enter a ciphertext:"))

        except ValueError:
            print("Invalid input, please enter a valid integer value.")
            continue
        else:
            # successful value entered
            break

    print("Cracking the ciphertext")
    # To find p and q we have to factor n. We can use the Pollards Rho Algorithm to find one factor (p or q)
    # and then divide n by that factor to find the other value (p or q)
    f1 = pollardrho(n)
    f2 = (n // f1)

    # After finding p and q we can find phi(n) and then do th
    phi_n = (f1 - 1) * (f2 - 1)

    # Now we can calculate d which is the inverse of e in Z^x phi(n)
    d = multInverse(e, phi_n)

    # Finally we can find the original message
    cleartext = fast_exp(encryptmsg, d, n)
    print("Factor 1 is:", f1, "Factor 2 is:", f2, "The original message is", cleartext)


def main():
    menu1 = True
    while menu1:
        print("Daniel Eke CS789 Final Project.\n" 
              "Choose one of the encryption algorithms below to get started:")
        first_input = input("1.El Gamal \n"
                            "2.RSA \n"
                            "3.Exit \n"
                            "Enter Option:")
        if first_input == '1':
            menu(first_input)

        elif first_input == '2':
            menu(first_input)

        elif first_input == '3':
            break


main()