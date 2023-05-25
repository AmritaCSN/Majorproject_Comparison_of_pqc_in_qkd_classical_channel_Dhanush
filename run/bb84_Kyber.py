from Crypto.Hash.SHAKE256 import new
from qunetsim.components.host import Host
from qunetsim.components.network import Network
from qunetsim.objects import Qubit
from qunetsim.objects import Logger
from time import sleep
import random
import falcon
import pickle

from kyber.kyber import Kyber512
from kyber.polynomials import *
from docopt import docopt
from ntru.ntrucipher import NtruCipher
from ntru.mathutils import random_poly
from sympy.abc import x
from sympy import ZZ, Poly
from padding.padding import *
import numpy as np
import sys
import logging
import math
import sys


Logger.DISABLED = True
KEY_LENGTH = 200
SAMPLE_SIZE = int(KEY_LENGTH / 4)
WAIT_TIME = 50
INTERCEPTION = False

log = logging.getLogger("Kyber")

debug = False
verbose = False


def save_object(obj, filename):
    with open(filename, "wb") as outp:  # Overwrites any existing file.
        pickle.dump(obj, outp, pickle.HIGHEST_PROTOCOL)


def read_obj(filename):
    fp = open(filename, "rb")
    return pickle.load(fp)


def generate(priv_key_file, pub_key_file):
    pk, sk = Kyber512.keygen()
    np.savez_compressed(priv_key_file, sk=sk)
    log.info("Private key saved to {} file".format(priv_key_file))
    np.savez_compressed(pub_key_file, pk=pk)
    log.info("Public key saved to {} file".format(pub_key_file))


def encryption(pub_key_file, input_arr, bin_output=False, block=False):
    pub_key = np.load(pub_key_file, allow_pickle=True)
    pub_key = pub_key["pk"].tobytes()
    c, key = Kyber512.enc(pub_key, input_arr, 48)
    return c, key


def decrypt(c, input_arr, bin_input=False, block=False):
    deckey = Kyber512.dec(c, input_arr, 48)
    return deckey


#########################################################################
# Basis Declaration
BASIS = ["Z", "X"]  # |0>|1> = Z-Basis; |+>|-> = X-Basis
##########################################################################


def q_bit(host, encode):
    q = Qubit(host)
    if encode == "+":
        q.H()
    if encode == "-":
        q.X()
        q.H()
    if encode == "0":
        q.I()
    if encode == "1":
        q.X()
    return q


def encoded_bases(alice_bits, alice_basis):
    alice_encoded = ""
    for i in range(0, len(alice_bits)):
        if alice_basis[i] == "X":  # X-Basis
            if alice_bits[i] == "0":
                alice_encoded += "+"
            if alice_bits[i] == "1":
                alice_encoded += "-"
        if alice_basis[i] == "Z":  # Z-Basis
            if alice_bits[i] == "0":
                alice_encoded += "0"
            if alice_bits[i] == "1":
                alice_encoded += "1"
    # print("Alice encoded: {}".format(alice_encoded))
    return alice_encoded


def preparation():
    alice_basis = ""
    bob_basis = ""
    alice_bits = ""
    for kl in range(KEY_LENGTH):
        alice_basis += random.choice(BASIS)
        bob_basis += random.choice(BASIS)
        alice_bits += str(random.getrandbits(1))
    alice_encoded = encoded_bases(alice_bits, alice_basis)
    return alice_basis, bob_basis, alice_bits, alice_encoded


def alice(host, receiver, alice_basis, alice_bits, alice_encoded):
    # For Qubit and Basis
    for i, encode in enumerate(alice_encoded):
        _, ack = host.send_qubit(receiver, q_bit(host, encode), await_ack=True)
        if ack is not None:
            print("{}'s qubit {} successfully sent".format(host.host_id, i))
    ################################################################################

    # Generating signature of Alice
    sk = falcon.SecretKey(512)
    pk = falcon.PublicKey(sk)
    # msg = bytes(alice_basis,"utf8")
    encoded_string = alice_basis.encode()
    byte_array = bytearray(encoded_string)
    input_arr = np.unpackbits(np.frombuffer(byte_array, dtype=np.uint8))

    input_arr = np.trim_zeros(input_arr, "b")

    # Generating Public and Private Key of Alice
    generate("myKey.priv", "myKey.pub")

    # encryptioning Alice Basis
    c, output = encryption("myKey.pub.npz", input_arr, True, True)
    str_output = c
    sig = sk.sign(output)
    save_object(pk, "pkalice")
    save_object(sig, "sigalice")
    print("key produced at Alice", output)

    # Sending Basis to Bob
    ack_basis_alice = host.send_classical(receiver, str_output, await_ack=True)
    if ack_basis_alice is not None:
        print("{}'s basis string successfully sent".format(host.host_id))

    # Receiving Basis from Bob

    enc_basis_from_bob = host.get_classical(receiver, wait=WAIT_TIME)

    if enc_basis_from_bob:
        print("{}'s basis string got successfully by {}".format(receiver, host.host_id))
        enc_content_bob = enc_basis_from_bob[0].content

        # Decypting Bob Basis
        pub_key = np.load("bob_myKey.priv.npz", allow_pickle=True)
        key_extracted_bob = pub_key["sk"].tobytes()
        basis_from_bob = Kyber512.dec(enc_content_bob, key_extracted_bob, 48)

        # verifying Bob
        sleep(5)

        bl = basis_from_bob
        pp = read_obj("pkbob")
        sig = read_obj("sigbob")
        # msge = bytes(bl,"utf8")
        tr = pp.verify(bl, sig)
        if tr == True:
            print("Bob verified")

        else:
            print("Bob Not verified")
    ###############################################################################

    #################################################################################


def eve_sniffing_quantum(sender, receiver, qubit):
    qubit.measure(non_destructive=True)


def bob(host, receiver, bob_basis):
    bob_measured_bits = ""

    # For Qubit and Basis
    for i in range(0, len(bob_basis)):
        data = host.get_data_qubit(receiver, wait=WAIT_TIME)
        if data is not None:
            print(
                "{}'s qubit {} got successfully by {}".format(receiver, i, host.host_id)
            )

        # Measuring Alice's qubit based on Bob's basis
        if bob_basis[i] == "Z":  # Z-basis
            bob_measured_bits += str(data.measure())
        if bob_basis[i] == "X":  # X-basis
            data.H()
            bob_measured_bits += str(data.measure())
    # print("Bob measured bit: {}".format(bob_measured_bits))
    ###############################################################################

    # Generating signature of bob
    sk = falcon.SecretKey(512)
    pk = falcon.PublicKey(sk)
    encoded_string = bob_basis.encode()
    byte_array = bytearray(encoded_string)

    input_arr = np.unpackbits(np.frombuffer(byte_array, dtype=np.uint8))

    input_arr = np.trim_zeros(input_arr, "b")

    # Generating public and private key of Bob
    generate("bob_myKey.priv", "bob_myKey.pub")

    # encryption bob  Basis--> tbd
    c, output = encryption("bob_myKey.pub.npz", input_arr, True, True)
    bob_str_output = c
    # print('bob key',output)
    sig = sk.sign(output)
    save_object(pk, "pkbob")
    save_object(sig, "sigbob")

    # Sending Basis to Alice
    ack_basis_bob = host.send_classical(receiver, bob_str_output, await_ack=True)
    if ack_basis_bob is not None:
        print("{}'s basis string successfully sent".format(host.host_id))
    ################################################################################

    # Receiving Basis from Alice
    enc_basis_from_alice = host.get_classical(receiver, wait=WAIT_TIME)

    if enc_basis_from_alice:
        print("{}'s basis string got successfully by {}".format(receiver, host.host_id))

        enc_content_alice = enc_basis_from_alice[0].content
        pub_key_bob = np.load("myKey.priv.npz", allow_pickle=True)
        key_extracted = pub_key_bob["sk"].tobytes()
        basis_from_alice = Kyber512.dec(enc_content_alice, key_extracted, 48)
        print("key produced at BOB", basis_from_alice)

        # verifying Alice
        sleep(5)

        al = basis_from_alice

        pp = read_obj("pkalice")
        sig = read_obj("sigalice")
        # msge = bytes(al,"utf8")
        tr = pp.verify(al, sig)
        if tr == True:
            print("Alice verified")
        else:
            print("Alice Not verified")

    ##############################################################################


def main():
    network = Network.get_instance()
    nodes = ["Alice", "Eve", "Bob"]
    network.start(nodes)
    network.delay = 0.1

    host_alice = Host("Alice")
    host_alice.add_connection("Eve")
    host_alice.start()

    host_eve = Host("Eve")
    host_eve.add_connections(["Alice", "Bob"])
    host_eve.start()

    host_bob = Host("Bob")
    host_bob.add_connection("Eve")
    host_bob.delay = 0.4
    host_bob.start()

    network.add_host(host_alice)
    network.add_host(host_eve)
    network.add_host(host_bob)
    network.start()

    alice_basis, bob_basis, alice_bits, alice_encoded = preparation()
    print("Alice bases: {}".format(alice_basis))
    print("Bob bases: {}".format(bob_basis))
    print("Alice bits: {}".format(alice_bits))
    print("Alice encoded: {}".format(alice_encoded))

    if INTERCEPTION:
        host_eve.q_relay_sniffing = True
        host_eve.q_relay_sniffing_fn = eve_sniffing_quantum

    t1 = host_alice.run_protocol(
        alice,
        (
            host_bob.host_id,
            alice_basis,
            alice_bits,
            alice_encoded,
        ),
    )
    t2 = host_bob.run_protocol(
        bob,
        (
            host_alice.host_id,
            bob_basis,
        ),
    )
    t1.join()
    t2.join()

    network.stop(True)
    exit()


if __name__ == "__main__":
    main()
