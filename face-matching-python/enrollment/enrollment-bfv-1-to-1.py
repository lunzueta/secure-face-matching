import os
import sys
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
# Seems like 16 also works
parms.set_plain_modulus(PlainModulus.Batching(poly_modulus_degree, 20))

context = SEALContext(parms)
print("Set encryption parameters and print")
seal_helper.print_parameters(context)

keygen = KeyGenerator(context)
gal_key = keygen.create_galois_keys()
relin_key = keygen.create_relin_keys()
public_key = keygen.create_public_key()
secret_key = keygen.secret_key()

evaluator = Evaluator(context)
batch_encoder = BatchEncoder(context)
encryptor = Encryptor(context, public_key)
decryptor = Decryptor(context, secret_key)

# Save the keys (public, secret, relin and galois)
data_path = './data/'
name = data_path + 'public_key_bfv_1_to_1_py.bin'
public_key.save(name)
print("Saving Public Key: " + name)

name = data_path + 'secret_key_bfv_1_to_1_py.bin'
secret_key.save(name)
print("Saving Secret Key: " + name)

name = data_path + 'relin_key_bfv_1_to_1_py.bin'
relin_key.save(name)
print("Saving Relin Keys: " + name)

name = data_path + 'galois_key_bfv_1_to_1_py.bin'
gal_key.save(name)
print("Saving Galois Keys: " + name)
slot_count = int(batch_encoder.slot_count())

f = open(data_path + "gallery-1-to-1.bin", "rb")
num_gallery = int(np.fromfile(f, dtype=int, count=1))
dim_gallery = int(np.fromfile(f, dtype=int, count=1))

for i in range(num_gallery):
    # Load gallery from file
    gallery = np.fromfile(f, dtype=np.float32, count=dim_gallery)

    # Push gallery into a vector of size poly_modulus_degree
    # Actually we should be able to squeeze two gallery instances into one
    # vector
    # This depends on implementation, can get 2x speed up and 2x less storage
    row_size = int(slot_count / 2)
    pod_matrix = []
    for j in range(row_size):
        if 0 <= j and j < dim_gallery:
            pod_matrix.append(np.int64(round(precision * gallery[j])))
        else:
            pod_matrix.append(np.int64(0))

    # Encrypt entire vector of gallery
    plain_matrix = batch_encoder.encode(pod_matrix)
    print("Encrypting Gallery: " + str(i))
    encrypted_matrix = encryptor.encrypt(plain_matrix)

    # Save encrypted feature vector to disk.
    name = data_path + 'encrypted_gallery_bfv_1_to_1_' + str(i) + \
        '_py.bin'
    encrypted_matrix.save(name)

print("Done")
f.close()
