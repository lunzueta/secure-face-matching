import sys
import numpy as np
from seal import *
sys.path.insert(0, ".")
import seal_helper


precision = 125  # precision of 1/125 = 0.004
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

# Save the keys (public, secret, relin and galios)
data_path = 'C:/LUI/code/secure-face-matching/data/'
name = data_path + 'keys/public_key_bfv_1_to_1_py.bin'
public_key.save(name)
print("Saving Public Key: " + name)

name = data_path + 'keys/secret_key_bfv_1_to_1_py.bin'
secret_key.save(name)
print("Saving Secret Key: " + name)

name = data_path + 'keys/relin_key_bfv_1_to_1_py.bin'
relin_key.save(name)
print("Saving Relin Keys: " + name)

name = data_path + 'keys/galios_key_bfv_1_to_1_py.bin'
gal_key.save(name)
print("Saving Galios Keys: " + name)
slot_count = batch_encoder.slot_count()

f = open(data_path + "gallery-1-to-1.bin", "rb")
num_gallery = int(np.fromfile(f, dtype=int, count=1))
dim_gallery = int(np.fromfile(f, dtype=int, count=1))

for i in range(num_gallery):
    # Load gallery from file
    gallery = np.fromfile(f, dtype=float, count=dim_gallery)

    # Push gallery into a vector of size poly_modulus_degree
    # Actually we should be able to squeeze two gallery instances into one
    # vector
    # This depends on implementation, can get 2x speed up and 2x less storage

f.close()
