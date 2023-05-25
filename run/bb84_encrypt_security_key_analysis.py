import difflib
import time
from Crypto.Hash.SHAKE256 import new
from qunetsim.components.host import Host
from qunetsim.components.network import Network
from qunetsim.objects import Qubit
from qunetsim.objects import Logger
from time import sleep
import tracemalloc
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
KEY_LENGTH = 100
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


def decrypt(c, input_arr, key_length):
    pub_key = np.load(input_arr, allow_pickle=True)
    pub_key_sk = pub_key["sk"].tobytes()
    basis = Kyber512.dec(c, pub_key_sk, 48)
    return basis


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

    encoded_string = alice_basis.encode()
    byte_array = bytearray(encoded_string)
    input_arr = np.unpackbits(np.frombuffer(byte_array, dtype=np.uint8))

    input_arr = np.trim_zeros(input_arr, "b")

    # Generating Public and Private Key of Alice
    generate("myKey.priv", "myKey.pub")

    # encryptioning Alice Basis

    c, output = encryption("myKey.pub.npz", input_arr, True, True)
    data = np.load("myKey.pub.npz", allow_pickle=True)
    data = data["pk"]
    str_output = c
    enc_end = time.time()

    byte_data = bytearray(data)
    # Change the first bit of the first byte to 0
    byte_data[1] &= 0xFE

    # Convert back to bytes
    new_data = bytes(byte_data)
    filename = "myKey.pub.npz"
    filedic = dict(np.load("myKey.pub.npz", allow_pickle=True))
    filedic["pk"] = new_data
    np.savez(filename, **filedic)
    op_cipher, op_test = encryption("myKey.pub.npz", input_arr, True, True)

    ratio = difflib.SequenceMatcher(None, c, op_cipher).ratio()

    # Print the similarity ratio as a percentage
    print(f"The similarity between the two encryption byte arrays is {ratio/100:.5f}%")
    # Generating signature of Alice

    sk = falcon.SecretKey(512)
    pk = falcon.PublicKey(sk)
    sig = sk.sign(output)
    save_object(pk, "pkalice")
    save_object(sig, "sigalice")

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
        basis_from_bob = decrypt(enc_content_bob, "bob_myKey.priv.npz", 48)

        data1 = np.load("bob_myKey.priv.npz", allow_pickle=True)
        data1 = data1["sk"]
        byte_data = bytearray(data1)
        # Change the first bit of the first byte to 0
        byte_data[0] &= 0xFE
        byte_data[-1] = 0x13
        byte_data[-2] = 0x11
        # Convert back to bytes
        new_data1 = bytes(byte_data)
        filename = "bob_myKey.priv.npz"
        filedic = dict(np.load("bob_myKey.priv.npz", allow_pickle=True))
        filedic["sk"] = new_data1
        np.savez(filename, **filedic)
        basis_from_bob_test = decrypt(enc_content_bob, "bob_myKey.priv.npz", 48)

        t = 0

        for i in range(len(basis_from_bob_test)):
            if basis_from_bob[i] == basis_from_bob_test[i]:
                t = t + 1

        ratio = difflib.SequenceMatcher(
            None, basis_from_bob_test, basis_from_bob
        ).ratio()

        # Print the similarity ratio as a percentage
        print(f"The similarity between the two byte arrays is {ratio/100:.5f}%")
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
    print("Bob measured bit: {}".format(bob_measured_bits))
    ###############################################################################

    # Generating signature of bob
    sk = falcon.SecretKey(512)
    pk = falcon.PublicKey(sk)
    # msg = bytes(bob_basis,"utf8")

    encoded_string = bob_basis.encode()
    byte_array = bytearray(encoded_string)

    input_arr = np.unpackbits(np.frombuffer(byte_array, dtype=np.uint8))

    input_arr = np.trim_zeros(input_arr, "b")

    # Generating public and private key of Bob
    generate("bob_myKey.priv", "bob_myKey.pub")

    # encryption bob  Basis
    c, output = encryption("bob_myKey.pub.npz", input_arr, True, True)
    bob_str_output = c
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

        # Decypt Alice Basis
        basis_from_alice = decrypt(enc_content_alice, "myKey.priv.npz", 48)

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
    tracemalloc.start()
    total_start = time.time()
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
    # network.draw_classical_network()
    # network.draw_quantum_network()
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
    total_end = time.time()
    print(f"Total runtime of the program  {total_end - total_start}")
    exit()


if __name__ == "__main__":
    main()
