///////////// Copyright 2018 Vishnu Boddeti. All rights reserved. /////////////
//
//   Project     : Secure Face Matching
//   File        : enrollment-bfv-1-to-n.cpp
//   Description : user face enrollment, key generation, feature encryption,
//                 feature storage in database, key storage
//                 uses BFV scheme for 1:N matching
//
//   Created On: 05/01/2018
//   Created By: Vishnu Boddeti <mailto:vishnu@msu.edu>
//   Modified On: 03/01/2020
////////////////////////////////////////////////////////////////////////////

#include <fstream>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <chrono>
#include <random>
#include <thread>
#include <mutex>
#include <random>
#include <limits>

#include <time.h>
#include <cmath>

#include "seal/seal.h"
#include "utils.h"

using namespace std;
using namespace seal;

int main() {
    float precision;
    stringstream stream;
    size_t poly_modulus_degree;

    precision = 125; // precision of 1/125 = 0.004
    poly_modulus_degree = 32768;

    EncryptionParameters parms(scheme_type::bfv);
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    // Seems like 16 also works
    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));

    cout << "\nTotal memory allocated by global memory pool: "
        << (MemoryPoolHandle::Global().alloc_byte_count() >> 20) << " MB" << endl;

    auto context = make_shared<SEALContext>(parms);
    print_line(__LINE__);
    cout << "Set encryption parameters and print" << endl;
    print_parameters(context);

    KeyGenerator keygen(*context);
    GaloisKeys gal_key;
    keygen.create_galois_keys(gal_key);
    RelinKeys relin_key;
    keygen.create_relin_keys(relin_key);
    PublicKey public_key;
    keygen.create_public_key(public_key);
    SecretKey secret_key = keygen.secret_key();

    Evaluator evaluator(*context);
    BatchEncoder batch_encoder(*context);
    Encryptor encryptor(*context, public_key);
    Decryptor decryptor(*context, secret_key);

    int slot_count = batch_encoder.slot_count();
    cout << "Plaintext matrix slot count: " << slot_count << endl;

    string name;
    ofstream ofile;

    // Save the keys (public, secret, relin and galois)
    string data_path = "../../data/";
    name = data_path + "public_key_bfv_1_to_n.bin";
    cout << "Saving Public Key: " << name << endl;
    ofile.open(name.c_str(), ios::out|ios::binary);
    public_key.save(stream);
    ofile << stream.str();
    ofile.close();
    stream.str(std::string());
    cout << "Done saving public keys" << endl;

    name = data_path + "secret_key_bfv_1_to_n.bin";
    cout << "Saving Secret Key: " << name << endl;
    ofile.open(name.c_str(), ios::out|ios::binary);
    secret_key.save(stream);
    ofile << stream.str();
    ofile.close();
    stream.str(std::string());
    cout << "Done saving private keys" << endl;

    name = data_path + "relin_key_bfv_1_to_n.bin";
    cout << "Saving Relin Keys: " <<  name << endl;
    ofile.open(name.c_str(), ios::out|ios::binary);
    relin_key.save(stream);
    ofile << stream.str();
    ofile.close();
    stream.str(std::string());
    cout << "Done saving relinearization keys" << endl;

	ifstream ifile;
    int num_gallery, dim_gallery;
    ifile.open (data_path + "gallery-1-to-n.bin", ios::in|ios::binary);

    if (ifile.fail()) {
      cout << name + " does not exist" << endl;
    } else {
      ifile.read((char *)&dim_gallery, sizeof(int));
      ifile.read((char *)&num_gallery, sizeof(int));
    }

    cout << num_gallery << endl;
    cout << dim_gallery << endl;

    Plaintext plain_matrix;
    float* gallery = new float[num_gallery];
    vector<int64_t> pod_matrix;
    for (int i = 0; i < dim_gallery; ++i) {
        // Load gallery from file
        ifile.read((char *)&gallery, num_gallery * sizeof(float));

        // Push dim i of all gallery into a vector of size poly_modulus_degree
        // Assuming that gallery size is smaller than poly_modulus_degree
        // else need to chunk the gallery into blocks
        for (int j = 0; j < slot_count; ++j) {
            if ((0 <= j) && (j < num_gallery)) {
                int a = (int64_t) roundf(precision*gallery[j]);
                pod_matrix.push_back(a);
            } else {
                pod_matrix.push_back((int64_t) 0);
            }
        }

        // Encrypt entire dim of gallery
        Ciphertext encrypted_matrix;
        batch_encoder.encode(pod_matrix, plain_matrix);
        cout << "Encrypting Gallery Dim: " << i << endl;
        encryptor.encrypt(plain_matrix, encrypted_matrix);

        // Save encrypted feature vector to disk.
        name = data_path + "encrypted_gallery_bfv_1_to_n_" +
            std::to_string(i) + ".bin";
        ofile.open(name.c_str(), ios::out|ios::binary);
        encrypted_matrix.save(stream);
        ofile << stream.str();
        ofile.close();
        pod_matrix.clear();
        stream.str(std::string());
    }
    cout << "Done" << endl;
    ifile.close();
    delete [] gallery;
    return 0;
}
