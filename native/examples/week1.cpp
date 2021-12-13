//
// Created by WonSuk Kim on 2021/12/10.
//

#include "util.h"

#include <vector>
#include <iostream>
#include <numeric>

using namespace std;
using namespace seal;
#include <algorithm>
#include <chrono>

using namespace std;
using namespace seal;

class Stopwatch
{
public:
    Stopwatch(string timer_name) :
            name_(timer_name),
            start_time_(chrono::high_resolution_clock::now())
    {
    }

    ~Stopwatch()
    {
      auto end_time = chrono::high_resolution_clock::now();
      auto duration = chrono::duration_cast<chrono::milliseconds>(end_time - start_time_);
      cout << name_ << ": " << duration.count() << " milliseconds" << endl;
    }

private:
    string name_;
    chrono::steady_clock::time_point start_time_;
};


void week1()
{
  // CLIENT'S VIEW

  // Vector of inputs
  size_t dimension = 1000;

  vector<double> inputs;
  inputs.reserve(dimension);
  for (size_t i = 0; i < dimension; i++) {
    inputs.push_back(rand() % 100);
  };

  // Setting up encryption parameters
  EncryptionParameters parms(scheme_type::CKKS);
  size_t poly_modulus_degree = 32768;
  parms.set_poly_modulus_degree(poly_modulus_degree);
  parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 30, 60 }));

  // Set up the SEALContext
  auto context = SEALContext::Create(parms);

  cout << "Parameters are valid: " << boolalpha
       << context->key_context_data()->qualifiers().parameters_set << endl;
  cout << "Maximal allowed coeff_modulus bit-count for this poly_modulus_degree: "
       << CoeffModulus::MaxBitCount(poly_modulus_degree) << endl;
  cout << "Current coeff_modulus bit-count: "
       << context->key_context_data()->total_coeff_modulus_bit_count() << endl;

  // Use a scale of 2^20 to encode
  double scale = pow(2.0, 30);

  // Create a vector of plaintexts
  CKKSEncoder encoder(context);
  Plaintext pt;
  encoder.encode(inputs, scale, pt);

  // Set up keys
  KeyGenerator keygen(context);
  auto sk = keygen.secret_key();
  auto pk = keygen.public_key();

  GaloisKeys galk;
  // Create rotation (Galois) keys
  {
    Stopwatch sw("GaloisKeys creation time");
    galk = keygen.galois_keys();
  }

  // Set up Encryptor
  Encryptor encryptor(context, pk);

  // Create ciphertext
  Ciphertext ct;
  {
    Stopwatch sw("Encryption time");
    encryptor.encrypt(pt, ct);
  }

  // Save to see size
  {
    ofstream fs("test.ct", ios::binary);
    ct.save(fs);
  }

  // Save GaloisKeys to see their size
  {
    ofstream fs("test.galk", ios::binary);
    galk.save(fs);
  }

  // Now send this vector to the server!
  // Also save and send the EncryptionParameters.



  // SERVER'S VIEW

  // Load EncryptionParameters and set up SEALContext

  vector<double> weights;
  weights.reserve(dimension);
  for (size_t i = 0; i < dimension; i++) {
    weights.push_back(1/(double)dimension);
  }

  Plaintext weight_pt;
  {
    Stopwatch sw("Encoding time");
    encoder.encode(weights, scale, weight_pt);
  }

  // Create the Evaluator
  Evaluator evaluator(context);

  {
    Stopwatch sw("Multiply-plain and rescale time");

    evaluator.multiply_plain_inplace(ct, weight_pt);
    evaluator.rescale_to_next_inplace(ct);
//    ct.scale() = pow(2, 30);
  }


  // Sum the slots
  {
    Stopwatch sw("Sum-the-slots time");
    for (size_t i = 1; i <= encoder.slot_count() / 2; i <<= 1) {
      Ciphertext temp_ct;
      evaluator.rotate_vector(ct, i, galk, temp_ct);
      evaluator.add_inplace(ct, temp_ct);
    }
  }



  // CLIENT'S VIEW ONCE AGAIN

  Decryptor decryptor(context, sk);

  // Decrypt the result
  Plaintext pt_result;
  {
    Stopwatch sw("Decryption time");
    decryptor.decrypt(ct, pt_result);
  }

  // Decode the result
  vector<double> vec_result;
  encoder.decode(pt_result, vec_result);
  cout << "Result: " << vec_result[0] << endl;
  cout << "True result: " << inner_product(inputs.cbegin(), inputs.cend(), weights.cbegin(), 0.0) << endl;
}




int main()
{
#ifdef SEAL_VERSION
  cout << "Microsoft SEAL version: " << SEAL_VERSION << endl;
#endif

  week1();

}
