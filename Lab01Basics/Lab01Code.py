#####################################################
# GA17 Privacy Enhancing Technologies -- Lab 01
#
# Basics of Petlib, encryption, signatures and
# an end-to-end encryption system.
#
# Run the tests through:
# $ py.test-2.7 -v Lab01Tests.py 

###########################
# Group Members: TODO
###########################


#####################################################
# TASK 1 -- Ensure petlib is installed on the System
#           and also pytest. Ensure the Lab Code can 
#           be imported.

import petlib

#####################################################
# TASK 2 -- Symmetric encryption using AES-GCM 
#           (Galois Counter Mode)
#
# Implement a encryption and decryption function
# that simply performs AES_GCM symmetric encryption
# and decryption using the functions in petlib.cipher.

from os import urandom
from petlib.cipher import Cipher

def encrypt_message(K, message):
    """ Encrypt a message under a key K """
    
    plaintext = message.encode("utf8")
    
    ## YOUR CODE HERE
    aes = Cipher.aes_128_gcm()  #init AES cipher with 128 bits key size
    iv = urandom(16)  #generate random initialisation vector of length 16 bytes
    
    ciphertext, tag = aes.quick_gcm_enc(K, iv, plaintext)  #GCM encryption returning ciphertext and tag
    
    return (iv, ciphertext, tag)

def decrypt_message(K, iv, ciphertext, tag):
    """ Decrypt a cipher text under a key K 

        In case the decryption fails, throw an exception.
    """
    ## YOUR CODE HERE
    aes = Cipher.aes_128_gcm()  
    plain = aes.quick_gcm_dec(K, iv, ciphertext, tag) #GCM decryption returning plaintext
    
    if plain == ciphertext: #fails if plain is same as ciphertext
        raise Exception("decryption failed")    
        
    return plain.encode("utf8")

#####################################################
# TASK 3 -- Understand Elliptic Curve Arithmetic
#           - Test if a point is on a curve.
#           - Implement Point addition.
#           - Implement Point doubling.
#           - Implement Scalar multiplication (double & add).
#           - Implement Scalar multiplication (Montgomery ladder).
#
# MUST NOT USE ANY OF THE petlib.ec FUNCIONS. Only petlib.bn!

from petlib.bn import Bn


def is_point_on_curve(a, b, p, x, y):
    """
    Check that a point (x, y) is on the curve defined by a,b and prime p.
    Reminder: an Elliptic Curve on a prime field p is defined as:

              y^2 = x^3 + ax + b (mod p)
                  (Weierstrass form)

    Return True if point (x,y) is on curve, otherwise False.
    By convention a (None, None) point represents "infinity".
    """
   
    assert isinstance(a, Bn)
    assert isinstance(b, Bn)
    assert isinstance(p, Bn) and p > 0
    assert (isinstance(x, Bn) and isinstance(y, Bn)) \
           or (x == None and y == None)

    if x is None and y is None:
        return True
    
    lhs = (y * y) % p
    rhs = (x*x*x + a*x + b) % p
    on_curve = (lhs == rhs)

    return on_curve


def point_add(a, b, p, x0, y0, x1, y1):
    """Define the "addition" operation for 2 EC Points.

    Reminder: (xr, yr) = (xq, yq) + (xp, yp)
    is defined as:
        lam = (yq - yp) * (xq - xp)^-1 (mod p)
        xr  = lam^2 - xp - xq (mod p)
        yr  = lam * (xp - xr) - yp (mod p)

    Return the point resulting from the addition. Raises an Exception if the points are equal.
    """

    # ADD YOUR CODE BELOW
    if is_point_on_curve(a, b, p, x0, y0) and is_point_on_curve(a, b, p, x1, y1): #if point is one curve proceed
        if x1 is None and y1 is None: #if point x1,y1 is infinity, return x0,y0
            return (x0, y0)
            
        elif x0 is None and y0 is None:
            return (x1, y1)
        
        if x0 == x1 and y0 == y1: #if points re the same, exception
            raise Exception("EC Points must not be equal")
        
        elif x0 == x1 and y0 == y1.mod_mul(-1, p): #if x values are the same and y values are opposite of each other
            return (None, None)
        
        xp = x0
        yp = y0
        xq = x1
        yq = y1
    
        lam = (yq - yp) * (xq - xp).mod_inverse(p)
        xr  = ((lam * lam) - xp - xq) % p
        yr  = (lam * (xp - xr) - yp) % p
    else:
        raise Exception("Points are not on the curve")
    
    
    return (xr, yr)

def point_double(a, b, p, x, y):
    """Define "doubling" an EC point.
     A special case, when a point needs to be added to itself.

     Reminder:
        lam = (3 * xp ^ 2 + a) * (2 * yp) ^ -1 (mod p)
        xr  = lam ^ 2 - 2 * xp
        yr  = lam * (xp - xr) - yp (mod p)

    Returns the point representing the double of the input (x, y).
    """  

    # ADD YOUR CODE BELOW
    if is_point_on_curve(a, b, p, x, y):
        if x is None and y is None:
            return (None, None)
            
        xp = x
        yp = y
        
        lam = (3 * xp.pow(2) + a) * (2 * yp).mod_inverse(p)
        xr  = (lam.pow(2) - 2 * xp) % p
        yr  = (lam * (xp - xr) - yp) % p
    
        return xr, yr
    else:
        raise Exception("Points are not on the curve")

def point_scalar_multiplication_double_and_add(a, b, p, x, y, scalar):
    """
    Implement Point multiplication with a scalar:
        r * (x, y) = (x, y) + ... + (x, y)    (r times)

    Reminder of Double and Multiply algorithm: r * P
        Q = infinity
        for i = 0 to num_bits(P)-1
            if bit i of r == 1 then
                Q = Q + P
            P = 2 * P
        return Q

    """
    Q = (None, None)
    P = (x, y)
   
    for i in range(scalar.num_bits()):
        if scalar.is_bit_set(i): #if bit == 1
            Q = point_add(a, b, p, Q[0], Q[1], P[0], P[1])
        P = point_double(a, b, p, P[0], P[1])

    return Q

def point_scalar_multiplication_montgomerry_ladder(a, b, p, x, y, scalar):
    """
    Implement Point multiplication with a scalar:
        r * (x, y) = (x, y) + ... + (x, y)    (r times)

    Reminder of Double and Multiply algorithm: r * P
        R0 = infinity
        R1 = P
        for i in num_bits(P)-1 to zero:
            if di = 0:
                R1 = R0 + R1
                R0 = 2R0
            else
                R0 = R0 + R1
                R1 = 2 R1
        return R0

    """
    R0 = (None, None)
    R1 = (x, y)

    for i in reversed(range(0,scalar.num_bits())):
        if not scalar.is_bit_set(i): #if bit == 0
            R1 = point_add(a, b, p, R0[0], R0[1], R1[0], R1[1])
            R0 = point_double(a, b, p, R0[0], R0[1])
        else:
            R0 = point_add(a, b, p, R0[0], R0[1], R1[0], R1[1])
            R1 = point_double(a, b, p, R1[0], R1[1])

    return R0


#####################################################
# TASK 4 -- Standard ECDSA signatures
#
#          - Implement a key / param generation 
#          - Implement ECDSA signature using petlib.ecdsa
#          - Implement ECDSA signature verification 
#            using petlib.ecdsa

from hashlib import sha256
from petlib.ec import EcGroup
from petlib.ecdsa import do_ecdsa_sign, do_ecdsa_verify

def ecdsa_key_gen():
    """ Returns an EC group, a random private key for signing 
        and the corresponding public key for verification"""
    G = EcGroup()
    priv_sign = G.order().random()
    pub_verify = priv_sign * G.generator()
    return (G, priv_sign, pub_verify)


def ecdsa_sign(G, priv_sign, message):
    """ Sign the SHA256 digest of the message using ECDSA and return a signature """
    plaintext =  message.encode("utf8")

    ## YOUR CODE HERE
    digest = sha256(plaintext).digest() #has plaintext using sha256 hashfunction
    sig = do_ecdsa_sign(G, priv_sign, digest) #sign using function using private key

    return sig

def ecdsa_verify(G, pub_verify, message, sig):
    """ Verify the ECDSA signature on the message """
    plaintext =  message.encode("utf8")

    ## YOUR CODE HERE
    digest = sha256(plaintext).digest() #hash
    res = do_ecdsa_verify(G, pub_verify, sig, digest) #returns true if decryption signature using public key == digest
    
    return res

#####################################################
# TASK 5 -- Diffie-Hellman Key Exchange and Derivation
#           - use Bob's public key to derive a shared key.
#           - Use Bob's public key to encrypt a message.
#           - Use Bob's private key to decrypt the message.
#
# NOTE: 

def dh_get_key():
    """ Generate a DH key pair """
    G = EcGroup()
    priv_dec = G.order().random()
    pub_enc = priv_dec * G.generator()
    return (G, priv_dec, pub_enc)


def dh_encrypt(pub, message, aliceSig = None):
    """ Assume you know the public key of someone else (Bob), 
    and wish to Encrypt a message for them.
        - Generate a fresh DH key for this message.
        - Derive a fresh shared key.
        - Use the shared key to AES_GCM encrypt the message.
        - Optionally: sign the message with Alice's key.
    """
    
    ## YOUR CODE HERE
    if aliceSig is None: #catch None case
        G, aliceSig, fresh_pub = dh_get_key()  #generate fresh DH key pair
        
    shared_key = aliceSig * pub  #derive shared key with Alices private key and Bobs public key
    shared_key_string = str(shared_key) #convert to string
    shared_key_trunc = shared_key_string[0:16] #only take first 16 bytes of key since shared key is the same
    
    iv, ciphertext, tag = encrypt_message(shared_key_trunc, message)  #AES GCM encrypt using shared key
    cipherpack = (fresh_pub, iv, ciphertext, tag) #return as tuple 
    
    return cipherpack
    

def dh_decrypt(priv, ciphertext, aliceVer = None):
    """ Decrypt a received message encrypted using your public key, 
    of which the private key is provided. Optionally verify 
    the message came from Alice using her verification key."""
    
    ## YOUR CODE HERE
    if aliceVer is None: 
        aliceVer = ciphertext[0]
        
    iv = ciphertext[1]
    cipher = ciphertext[2]
    tag = ciphertext[3]
   
    shared_key = priv * aliceVer  #derive shared key using Bobs private key and Alices public key
    shared_key_string = str(shared_key)
    shared_key_trunc = shared_key_string[0:16]
    
    plaintext = decrypt_message(shared_key_trunc, iv, cipher, tag)
    
    return plaintext

## NOTE: populate those (or more) tests
#  ensure they run using the "py.test filename" command.
#  What is your test coverage? Where is it missing cases?
#  $ py.test-2.7 --cov-report html --cov Lab01Code Lab01Code.py 

def test_encrypt():
    G, priv, pub = dh_get_key()  #Bobs key pair
    message = u"Hello World!"
    cipherpack = dh_encrypt(pub, message)
    
    fresh_pub = cipherpack[0]
    iv = cipherpack[1]
    ciphertext = cipherpack[2]
    tag = cipherpack[3]
    
    
    assert len(iv) == 16
    assert len(ciphertext) == len(message)
    assert len(tag) == 16

    assert fresh_pub != pub

def test_decrypt():
    G, priv, pub = dh_get_key()
    message = u"Hello World!"
    cipherpack = dh_encrypt(pub, message)
    
    fresh_pub = cipherpack[0]
    assert fresh_pub != pub #alices public key
    
    plain = dh_decrypt(priv, cipherpack)
    assert plain == message

def test_fails():
    from pytest import raises
    
    G, priv, pub = dh_get_key()
    message = u"Hello World!"
    cipherpack = dh_encrypt(pub, message)
    
    #random ciphertext
    cipherpack_1 = (cipherpack[0], cipherpack[1], urandom(len(cipherpack[2])), cipherpack[3])
    with raises(Exception) as excinfo:
        dh_decrypt(priv, cipherpack_1)
    assert 'decryption failed' in str(excinfo.value)
    
    #random tag
    cipherpack_2 = (cipherpack[0], cipherpack[1], cipherpack[2], urandom(len(cipherpack[3])))
    with raises(Exception) as excinfo:
        dh_decrypt(priv, cipherpack_2)
    assert 'decryption failed' in str(excinfo.value)
    
    #random iv
    cipherpack_3 = (cipherpack[0], urandom(len(cipherpack[1])), cipherpack[2], cipherpack[3])
    with raises(Exception) as excinfo:
        dh_decrypt(priv, cipherpack_3)
    assert 'decryption failed' in str(excinfo.value)

    G, fail_priv, fail_pub = dh_get_key()
    
    #different public key for bob
    cipherpack_4 = (fail_pub, cipherpack[1], cipherpack[2], cipherpack[3])
    with raises(Exception) as excinfo:
        dh_decrypt(priv, cipherpack_4)
    assert 'decryption failed' in str(excinfo.value)
    
    #different private key for bob
    with raises(Exception) as excinfo:
        dh_decrypt(fail_priv, cipherpack)
    assert 'decryption failed' in str(excinfo.value)

#####################################################
# TASK 6 -- Time EC scalar multiplication
#             Open Task.
#           
#           - Time your implementations of scalar multiplication
#             (use time.clock() for measurements)for different 
#              scalar sizes)
#           - Print reports on timing dependencies on secrets.
#           - Fix one implementation to not leak information.

def time_scalar_mul():
    pass
