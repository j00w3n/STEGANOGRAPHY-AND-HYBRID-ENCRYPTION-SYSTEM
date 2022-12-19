import random
import math

def checking_if_is_prime(N):

    i = 2
    while i < N:
        R = N % i
        if R == 0:
            return False
        i += 1
    else:
        return N


def generating_keys():

    two_primes = []

    while len(two_primes) != 2:

        prime_number = checking_if_is_prime(random.randint(10**1, 10**2))

        while prime_number == False:
            prime_number = checking_if_is_prime(random.randint(10**1, 10**2))

        else:
            two_primes.append(prime_number)

    p = two_primes[0]
    q = two_primes[1]
    N = math.prod(two_primes)
    totiente = (p-1)*(q-1)

    def prime_between_themselves(e, totiente):

        i = 2
        while i <= e:
            R = totiente % i
            R2 = e % i 
            if R == 0 and R2 == 0:
                return False
            
            i += 1
        
        else:
            return True

    valid_e = False

    while not valid_e:

        e = random.randint(2, totiente-1)

        valid_e = prime_between_themselves(e, totiente)

    d = 1

    while True:

        if e * d % totiente == 1:
            break
    
        d += 1

    public_key = [e, N]
    private_key = [d, N]

    #print(f"p={p}\nq={q}\nN={N}\nTotiente={totiente}\ne={e}\nd={d}\n\n\nPublic Key = [{e}, {N}]\n\nPrivate Key = [{d}, {N}]")

    return public_key, private_key


def encrypt(message, public_key):

    e = public_key[0]
    n = public_key[1]
    secret = ""

    for char in str(message):

        secret += chr(ord(char)**e % n)

    return secret


def decrypt(secret, private_key):

    d = private_key[0]
    n = private_key[1]
    message = ""

    for char in str(secret):

        message += chr(ord(char)**d % n)

    return message


def private_key_digital_signature(private_key):

    valid_key_message = "This message was encrypted with my private key, it can only be decrypted with my public key. If you can understand this, it means that the key used to decrypt was a public key, the communication logo is secure."
    
    valid_secret_message = encrypt(valid_key_message, private_key)

    return valid_secret_message


def validating_digital_signature(valid_secret_message, public_key):

    valid_signature = decrypt(valid_secret_message, public_key)

    return valid_signature