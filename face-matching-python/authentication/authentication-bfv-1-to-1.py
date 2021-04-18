import os
import sys
import math
import numpy as np
from seal import *

PACKAGE_PARENT = '..'
SCRIPT_DIR = os.path.dirname(os.path.realpath(os.path.join(os.getcwd(),
    os.path.expanduser(__file__))))
sys.path.append(os.path.normpath(os.path.join(SCRIPT_DIR, PACKAGE_PARENT)))

from utils import seal_helper

precision = float(125)  # precision of 1/125 = 0.004
poly_modulus_degree = 4096

parms = EncryptionParameters(scheme_type.bfv)
parms.set_poly_modulus_degree(poly_modulus_degree)
parms.set_coeff_modulus(CoeffModulus.BFVDefault(poly_modulus_degree))
parms.set_plain_modulus(PlainModulus.Batching(poly_modulus_degree, 20))

context = SEALContext(parms)
print("Set encryption parameters and print")
seal_helper.print_parameters(context)

# Load back the keys (public, secret, relin and galois)
data_path = 'C:/LUI/code/secure-face-matching/data/'
public_key = PublicKey()
name = data_path + 'keys/public_key_bfv_1_to_1_py.bin'
print("Loading Public Key: " + name)
public_key.load(context, name)

secret_key = SecretKey()
name = data_path + 'keys/secret_key_bfv_1_to_1_py.bin'
print("Loading Secret Key: " + name)
secret_key.load(context, name)

gal_key = GaloisKeys()
name = data_path + 'keys/galois_key_bfv_1_to_1_py.bin'
print("Loading Galois Keys: " + name)
gal_key.load(context, name)

relin_key = RelinKeys()
name = data_path + 'keys/relin_key_bfv_1_to_1_py.bin'
print("Loading Relin Keys: " + name)
relin_key.load(context, name)

encryptor = Encryptor(context, public_key)
evaluator = Evaluator(context)
decryptor = Decryptor(context, secret_key)
batch_encoder = BatchEncoder(context)
slot_count = batch_encoder.slot_count()
row_size = int(slot_count / 2)

# Load the gallery
num_gallery = 16
encrypted_gallery = []
for i in range(num_gallery):
    name = data_path + "gallery/encrypted_gallery_bfv_1_to_1_" + str(i) + \
        "_py.bin"
    encrypted_matrix = Ciphertext()
    encrypted_matrix.load(context, name)
    encrypted_gallery.append(encrypted_matrix)

f = open(data_path + "probe-1-to-1.bin", "rb")
num_probe = int(np.fromfile(f, dtype=int, count=1))
dim_probe = int(np.fromfile(f, dtype=int, count=1))

for i in range(num_probe):
    # Load probe from file
    probe = np.fromfile(f, dtype=np.float32, count=dim_probe)

    # Push probe into a vector of size poly_modulus_degree
    # Actually we should be able to squeeze two probe instances into one vector
    # This depends on implementation, can get 2x speed up and 2x less storage
    pod_vector = []
    for j in range(row_size):
        if 0 <= j and j < dim_probe:
            pod_vector.append(np.int64(round(precision * probe[j])))
        else:
            pod_vector.append(np.int64(0))

    # Encrypt entire vector of probe
    plain_probe = batch_encoder.encode(pod_vector)
    print("Encrypting Probe: " + str(i))
    encrypted_probe = encryptor.encrypt(plain_probe)

    for j in range(num_gallery):
        temp = Ciphertext(encrypted_probe)
        evaluator.multiply_inplace(temp, encrypted_gallery[j])
        evaluator.relinearize_inplace(temp, relin_key)
        encrypted_result = Ciphertext(temp)
        for k in range(int(math.log2(row_size))):
            temp = evaluator.rotate_rows(encrypted_result, int(math.pow(2, k)),
                gal_key)
            evaluator.add_inplace(encrypted_result, temp)
        
        plain_result = decryptor.decrypt(encrypted_result)
        pod_result = batch_encoder.decode(plain_result)

        score = float(pod_result[0]) / (precision * precision)
        print("Matching Score (probe " + str(i) + ", and gallery " + str(j) + \
            "): " + str(score))
    print("")

print("Done")
f.close()
