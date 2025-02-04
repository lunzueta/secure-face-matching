///////////// Copyright 2018 Vishnu Boddeti. All rights reserved. /////////////
//
//   Project     : Secure Face Matching
//   File        : authentication-bfv-1-to-1.cpp
//   Description : user face authentication, probe feature encryption,
//                 probe feature matching with encrypted database, decrypt matching score
//                 uses BFV scheme for 1:1 matching
//   Input       : needs gallery size as input
//
//   Created On: 05/01/2018
//   Created By: Vishnu Boddeti <mailto:vishnu@msu.edu>
//   Modified On: 03/01/2020
////////////////////////////////////////////////////////////////////////////

#include <fstream>
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

int main(int argc, char **argv) {
    // cout << argv[1] << endl;
    // int num_gallery = atoi(argv[1]);
    int num_gallery = 16;

    float precision;
    vector<int64_t> pod_result;

    GaloisKeys gal_key;
    RelinKeys relin_key;
    PublicKey public_key;
    SecretKey secret_key;

    precision = 125;  // precision of 1/125 = 0.004
    size_t poly_modulus_degree = 4096;

    EncryptionParameters parms(scheme_type::bfv);
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));

    cout << "\nTotal memory allocated by global memory pool: "
        << (MemoryPoolHandle::Global().alloc_byte_count() >> 20) << " MB"
        << endl;

    auto context = make_shared<SEALContext>(parms);
    print_line(__LINE__);
    cout << "Set encryption parameters and print" << endl;
    print_parameters(context);

    ifstream ifile;
    string name;
    stringstream stream;

    // Load back the keys (public, secret, relin and galois)
    string data_path = "../../data/";
    name = data_path + "public_key_bfv_1_to_1.bin";
    cout << "Loading Public Key: " << name << endl;
    ifile.open(name.c_str(), ios::in|ios::binary);
    if (ifile.fail()) {
        cout << name + " does not exist" << endl;
    }
    else{
        stream << ifile.rdbuf();
        public_key.unsafe_load(*context, stream);
    }
    ifile.close();
    stream.str(std::string());

    name = data_path + "secret_key_bfv_1_to_1.bin";
    cout << "Loading Private Key: " << name << endl;
    ifile.open(name.c_str(), ios::out|ios::binary);
    if (ifile.fail()) {
        cout << name + " does not exist" << endl;
    }
    else{
        stream << ifile.rdbuf();
        secret_key.unsafe_load(*context, stream);
    }
    ifile.close();
    stream.str(std::string());

    name = data_path + "galois_key_bfv_1_to_1.bin";
    cout << "Loading Galois Keys: " << name << endl;
    ifile.open(name.c_str(), ios::out|ios::binary);
    if (ifile.fail()) {
        cout << name + " does not exist" << endl;
    }
    else{
        stream << ifile.rdbuf();
        gal_key.unsafe_load(*context, stream);
    }
    ifile.close();
    stream.str(std::string());

    name = data_path + "relin_key_bfv_1_to_1.bin";
    cout << "Loading Relin Keys: " << name << endl;
    ifile.open(name.c_str(), ios::out|ios::binary);
    if (ifile.fail()) {
        cout << name + " does not exist" << endl;
    }
    else{
        stream << ifile.rdbuf();
        relin_key.unsafe_load(*context, stream);
    }
    ifile.close();
    stream.str(std::string());

    Encryptor encryptor(*context, public_key);
    Evaluator evaluator(*context);
    Decryptor decryptor(*context, secret_key);
    BatchEncoder batch_encoder(*context);
    int slot_count = batch_encoder.slot_count();
    int row_size = int(slot_count / 2);

    // Load the gallery
    vector<Ciphertext> encrypted_gallery;
    for (int i = 0; i < num_gallery; ++i) {
        name = data_path + "encrypted_gallery_bfv_1_to_1_" +
            std::to_string(i) + ".bin";
        ifile.open(name.c_str(), ios::in|ios::binary);
        Ciphertext encrypted_matrix;
        stream << ifile.rdbuf();
        encrypted_matrix.load(*context, stream);
        ifile.close();
        encrypted_gallery.push_back(encrypted_matrix);
    }

    int num_probe, dim_probe;
    ifile.open(data_path + "probe-1-to-1.bin", ios::in|ios::binary);
    
    ifile.read((char *)&num_probe, sizeof(int));
    ifile.read((char *)&dim_probe, sizeof(int));

    float score;
    float* probe = new float[dim_probe];
    vector<int64_t> pod_vector;
    Plaintext plain_probe;
    for (int i = 0; i < num_probe; ++i) {
        // Load probe from file
        ifile.read((char *)probe, dim_probe * sizeof(float));

        // Push probe into a vector of size poly_modulus_degree
        // Actually we should be able to squeeze two probe instances into one
        // vector
        // This depends on implementation, can get 2x speed up and 2x less
        // storage
        for (int j = 0; j < row_size; ++j) {
            if ((0 <= j) && (j < dim_probe)) {
                int a = (int64_t)roundf(precision * probe[j]);
                pod_vector.push_back(a);
            } else {
                pod_vector.push_back((int64_t) 0);
            }
        }

        // Encrypt entire vector of probe
        batch_encoder.encode(pod_vector, plain_probe);
        cout << "Encrypting Probe: " << i << endl;
        Ciphertext encrypted_probe;
        encryptor.encrypt(plain_probe, encrypted_probe);

        pod_vector.clear();
        vector<int64_t> pod_result;

        for (int j = 0; j < num_gallery; ++j) {
            Ciphertext temp = Ciphertext(encrypted_probe);
            evaluator.multiply_inplace(temp, encrypted_gallery[j]);
            evaluator.relinearize_inplace(temp, relin_key);
            Ciphertext encrypted_result = Ciphertext(temp);
            for (int k = 0; k < log2(row_size); ++k) {
                evaluator.rotate_rows(encrypted_result, pow(2, k), gal_key,
                    temp);
                evaluator.add_inplace(encrypted_result, temp);
            }

            Plaintext plain_result;
            decryptor.decrypt(encrypted_result, plain_result);
            batch_encoder.decode(plain_result, pod_result);

            score = float(pod_result[0]) / (precision * precision);
            cout << "Matching Score (probe " << i << ", and gallery " << j
                << "): " << score << endl;
            pod_vector.clear();
        }
        cout << " " << endl;
    }
    cout << "Done" << endl;
    ifile.close();
    delete [] probe;
    return 0;
}
