//https://gist.github.com/kobigurk/24c25e68219df87c348f1a78db51bb52
#include <iostream>

#include "wraplibsnarkgadgets.hpp"

#include "libsnark/gadgetlib1/gadget.hpp"
#include "libsnark/gadgetlib1/protoboard.hpp"
#include "libff/common/default_types/ec_pp.hpp"
#include "libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_components.hpp"
#include "libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp"

#include "libsnark/gadgetlib1/gadgets/merkle_tree/merkle_tree_check_read_gadget.hpp"
#include <libsnark/common/data_structures/merkle_tree.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/crh_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/digest_selector_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/hash_io.hpp>
#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_authentication_path_variable.hpp>

#include <libff/common/utils.hpp>

#include <libsnark/common/default_types/r1cs_ppzkpcd_pp.hpp>
#include <libsnark/common/default_types/r1cs_ppzksnark_pp.hpp>
#include <libsnark/relations/ram_computations/rams/fooram/fooram_params.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/ram_ppzksnark/examples/run_ram_ppzksnark.hpp>
#include <libsnark/zk_proof_systems/zksnark/ram_zksnark/examples/run_ram_zksnark.hpp>

#include <numeric>

#include <libsnark/gadgetlib1/gadgets/delegated_ra_memory/memory_load_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/delegated_ra_memory/memory_load_store_gadget.hpp>
#include <libsnark/relations/ram_computations/memory/delegated_ra_memory.hpp>
#include <libsnark/relations/ram_computations/rams/ram_params.hpp>
#include <libsnark/zk_proof_systems/pcd/r1cs_pcd/compliance_predicate/compliance_predicate.hpp>
#include <libsnark/zk_proof_systems/pcd/r1cs_pcd/compliance_predicate/cp_handler.hpp>

#include <openssl/sha.h>

#include <libsnark/zk_proof_systems/zksnark/ram_zksnark/ram_zksnark_params.hpp>

#include <sstream>

#include <libsnark/common/default_types/ram_zksnark_pp.hpp>
#include <libsnark/relations/ram_computations/rams/examples/ram_examples.hpp>
#include <libsnark/relations/ram_computations/rams/tinyram/tinyram_params.hpp>
#include <libsnark/zk_proof_systems/zksnark/ram_zksnark/examples/run_ram_zksnark.hpp>

using namespace libsnark;
using namespace libff;
using std::vector;

//typedef libff::Fr<alt_bn128_pp> FieldT;
typedef libff::Fr<default_ec_pp> FieldT;
//template<typename ppT>
//typedef ram_zksnark_machine_pp<ppT> ramT; //error: template declaration of 'typedef'
//using ramT = typename ram_zksnark_machine_pp<ppT>; //error: expected nested-name-specifier
//typedef ram_base_field<ramT> FieldT;

typedef CRH_with_bit_out_gadget<FieldT> HashT;


pb_variable_array<FieldT> from_bits(std::vector<bool> bits, pb_variable<FieldT>& ZERO)
{
    pb_variable_array<FieldT> acc;

    for (size_t i = 0; i < bits.size(); i++) {
        bool bit = bits[i];
        acc.emplace_back(bit ? ONE : ZERO);
    }

    return acc;
}

vector<unsigned long> bit_list_to_ints(vector<bool> bit_list, const size_t wordsize)
{
    vector<unsigned long> res;
    size_t iterations = bit_list.size()/wordsize+1;
    for (size_t i = 0; i < iterations; ++i) {
        unsigned long current = 0;
        for (size_t j = 0; j < wordsize; ++j) {
            if (bit_list.size() == (i*wordsize+j)) break;
            current += (bit_list[i*wordsize+j] * (1ul<<(wordsize-1-j)));
        }
        res.push_back(current);
    }
    return res;
}

class ethereum_sha256 : gadget<FieldT>
{
private:
    std::shared_ptr<block_variable<FieldT>> block1;
    std::shared_ptr<block_variable<FieldT>> block2;
    std::shared_ptr<digest_variable<FieldT>> intermediate_hash;

public:
    std::shared_ptr<sha256_compression_function_gadget<FieldT>> hasher2;
    std::shared_ptr<sha256_compression_function_gadget<FieldT>> hasher1;
    ethereum_sha256(
        protoboard<FieldT> &pb,
        pb_variable<FieldT>& ZERO,
        pb_variable_array<FieldT>& a,
        pb_variable_array<FieldT>& b,
        std::shared_ptr<digest_variable<FieldT>> result
    ) : gadget<FieldT>(pb, "ethereum_sha256") {

        intermediate_hash.reset(new digest_variable<FieldT>(pb, 256, "intermediate"));

        // As the hash is computed on the full 512bit block size
        // padding does not fit in the primary block
        // => add dummy block (single "1" followed by "0" + total length)
        pb_variable_array<FieldT> length_padding =
            from_bits({
                //dummy padding block
                1,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,

                //total length of message (512 bits)
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,1,0,
                0,0,0,0,0,0,0,0
            }, ZERO);

        block1.reset(new block_variable<FieldT>(pb, {
            a,
            b
        }, "block1"));

        block2.reset(new block_variable<FieldT>(pb, {
            length_padding
        }, "block2"));

        pb_linear_combination_array<FieldT> IV = SHA256_default_IV(pb);

        hasher1.reset(new sha256_compression_function_gadget<FieldT>(
            pb,
            IV,
            block1->bits,
            *intermediate_hash,
            "hasher1"));

        pb_linear_combination_array<FieldT> IV2(intermediate_hash->bits);

        hasher2.reset(new sha256_compression_function_gadget<FieldT>(
            pb,
            IV2,
            block2->bits,
            *result,
            "hasher2"));
    }

    void generate_r1cs_constraints() {
        hasher1->generate_r1cs_constraints();
        hasher2->generate_r1cs_constraints();
    }

    void generate_r1cs_witness() {
        hasher1->generate_r1cs_witness();
        hasher2->generate_r1cs_witness();
    }
};

// conversion byte[32] <-> libsnark bigint.
libff::bigint<libff::alt_bn128_r_limbs> libsnarkBigintFromBytesAux(const uint8_t* _x)
{
  libff::bigint<libff::alt_bn128_r_limbs> x;

  for (unsigned i = 0; i < 4; i++) {
    for (unsigned j = 0; j < 8; j++) {
      x.data[3 - i] |= uint64_t(_x[i * 8 + j]) << (8 * (7-j));
    }
  }
  return x;
}

void constraint_to_json(linear_combination<FieldT> constraints, std::stringstream &ss)
{
    ss << "{";
    uint count = 0;
    for (const linear_term<FieldT>& lt : constraints.terms)
    {
        if (count != 0) {
            ss << ",";
        }

        ss << '"' << lt.index << '"' << ":" << '"' << lt.coeff << '"';
        count++;
    }
    ss << "}";
}


std::string r1cs_to_json(protoboard<FieldT> pb)
{
    r1cs_constraint_system<FieldT> constraints = pb.get_constraint_system();
    std::stringstream ss;

    ss << "{\"input_count\":512, \"outputs\":[513,514,515,516,517,518,519,520,521,522,523,524,525,526,527,528,529,530,531,532,533,534,535,536,537,538,539,540,541,542,543,544,545,546,547,548,549,550,551,552,553,554,555,556,557,558,559,560,561,562,563,564,565,566,567,568,569,570,571,572,573,574,575,576,577,578,579,580,581,582,583,584,585,586,587,588,589,590,591,592,593,594,595,596,597,598,599,600,601,602,603,604,605,606,607,608,609,610,611,612,613,614,615,616,617,618,619,620,621,622,623,624,625,626,627,628,629,630,631,632,633,634,635,636,637,638,639,640,641,642,643,644,645,646,647,648,649,650,651,652,653,654,655,656,657,658,659,660,661,662,663,664,665,666,667,668,669,670,671,672,673,674,675,676,677,678,679,680,681,682,683,684,685,686,687,688,689,690,691,692,693,694,695,696,697,698,699,700,701,702,703,704,705,706,707,708,709,710,711,712,713,714,715,716,717,718,719,720,721,722,723,724,725,726,727,728,729,730,731,732,733,734,735,736,737,738,739,740,741,742,743,744,745,746,747,748,749,750,751,752,753,754,755,756,757,758,759,760,761,762,763,764,765,766,767,768],\"constraints\":[";

    for (size_t c = 0; c < constraints.num_constraints(); ++c)
    {
        ss << "[";// << "\"A\"=";
        constraint_to_json(constraints.constraints[c].a, ss);
        ss << ",";// << "\"B\"=";
        constraint_to_json(constraints.constraints[c].b, ss);
        ss << ",";// << "\"C\"=";;
        constraint_to_json(constraints.constraints[c].c, ss);
        if (c == constraints.num_constraints()-1 ) {
            ss << "]\n";
        } else {
            ss << "],\n";
        }
    }
    ss << "]}";
    ss.rdbuf()->pubseekpos(0, std::ios_base::out);
    return ss.str();
}

char* _shaEth256Constraints()
{
    libff::alt_bn128_pp::init_public_params();
    protoboard<FieldT> pb;

    pb_variable_array<FieldT> left;
    left.allocate(pb, 256, "left");

    pb_variable_array<FieldT> right;
    right.allocate(pb, 256, "right");

    std::shared_ptr<digest_variable<FieldT>> output;
    output.reset(new digest_variable<FieldT>(pb, 256, "output"));

    pb_variable<FieldT> ZERO;
    ZERO.allocate(pb, "ZERO");
    pb.val(ZERO) = 0;

    ethereum_sha256 g(pb, ZERO, left, right, output);
    g.generate_r1cs_constraints();

    auto json = r1cs_to_json(pb);

    auto result = new char[json.size()];
    memcpy(result, json.c_str(), json.size() + 1);
    return result;
}

std::string array_to_json(protoboard<FieldT> pb)
{
    std::stringstream ss;
    r1cs_variable_assignment<FieldT> values = pb.full_variable_assignment();
    ss << "{\"variables\":[";

    ss << 1 << ","; // the variable zero to the one constant

    for (size_t i = 0; i < values.size(); ++i)
    {
        ss << values[i].as_bigint();
        if (i <  values.size() - 1) { ss << ",";}
    }

    ss << "]}";
    ss.rdbuf()->pubseekpos(0, std::ios_base::out);

    return(ss.str());
}

char* _shaEth256Witness(const uint8_t* inputs, int inputs_length)
{

    libff::alt_bn128_pp::init_public_params();
    protoboard<FieldT> pb;

    pb_variable_array<FieldT> left;
    left.allocate(pb, 256, "left");
    pb_variable_array<FieldT> right;
    right.allocate(pb, 256, "right");

    std::shared_ptr<digest_variable<FieldT>> output;
    output.reset(new digest_variable<FieldT>(pb, 256, "output"));

    pb_variable<FieldT> ZERO;
    ZERO.allocate(pb, "ZERO");
    pb.val(ZERO) = 0;

    libff::bit_vector left_bv;
    libff::bit_vector right_bv;

    for (int i = 0; i < inputs_length / 2; i++) {
        std::cerr << libsnarkBigintFromBytesAux(inputs + i*32) << "\n";
        left_bv.push_back(libsnarkBigintFromBytesAux(inputs + i*32) == 1);
    }

    for (int i = inputs_length / 2; i < inputs_length; i++) {
        std::cerr << libsnarkBigintFromBytesAux(inputs + i*32) << "\n";
        right_bv.push_back(libsnarkBigintFromBytesAux(inputs + i*32) == 1);
    }

    left.fill_with_bits(pb, left_bv);
    right.fill_with_bits(pb, right_bv);


    ethereum_sha256 g(pb, ZERO, left, right, output);
    g.generate_r1cs_constraints();
    g.generate_r1cs_witness();

    assert(pb.is_satisfied());

    auto json = array_to_json(pb);

    auto result = new char[json.size()];
    memcpy(result, json.c_str(), json.size() + 1);
    return result;
}

char* _sha256Constraints()
{
    libff::alt_bn128_pp::init_public_params();
    protoboard<FieldT> pb;

    digest_variable<FieldT> left(pb, SHA256_digest_size, "left");
    digest_variable<FieldT> right(pb, SHA256_digest_size, "right");
    digest_variable<FieldT> output(pb, SHA256_digest_size, "output");

    sha256_two_to_one_hash_gadget<FieldT> f(pb, left, right, output, "f");
    f.generate_r1cs_constraints();

    auto json = r1cs_to_json(pb);

    auto result = new char[json.size()];
    memcpy(result, json.c_str(), json.size() + 1);
    return result;
}

char* _sha256Witness(const uint8_t* inputs, int inputs_length)
{

    libff::alt_bn128_pp::init_public_params();

    protoboard<FieldT> pb;

    digest_variable<FieldT> left(pb, SHA256_digest_size, "left");
    digest_variable<FieldT> right(pb, SHA256_digest_size, "right");
    digest_variable<FieldT> output(pb, SHA256_digest_size, "output");

    sha256_two_to_one_hash_gadget<FieldT> f(pb, left, right, output, "f");
    f.generate_r1cs_constraints(true);

    libff::bit_vector left_bv;
    libff::bit_vector right_bv;

    for (int i = 0; i < inputs_length / 2; i++) {
        left_bv.push_back(libsnarkBigintFromBytesAux(inputs + i*32) == 1);
    }
    for (int i = inputs_length / 2; i < inputs_length; i++) {
        right_bv.push_back(libsnarkBigintFromBytesAux(inputs + i*32) == 1);
    }

    left.generate_r1cs_witness(left_bv);
    right.generate_r1cs_witness(right_bv);

    f.generate_r1cs_witness();

    assert(pb.is_satisfied());

    auto json = array_to_json(pb);
    auto result = new char[json.size()];
    memcpy(result, json.c_str(), json.size() + 1);
    return result;
}

//template<typename ppT> //undefined reference to `_merkleReadConstraints' [when building zokrates_cli]
char* _merkleReadConstraints()
{
    //typedef ram_zksnark_machine_pp<ppT> ramT; //error: could not convert 'pb' from 'libsnark::protoboard<int>' to 'libsnark::protoboard<libff::Fp_model<4, ((const libff::bigint<4>&)(& libff::alt_bn128_modulus_r))> >' [when building zokrates_core]
    //typedef ram_base_field<ramT> FieldT;
    //typedef CRH_with_bit_out_gadget<FieldT> HashT;

  //see test: https://github.com/scipr-lab/libsnark/blob/master/libsnark/gadgetlib1/gadgets/merkle_tree/merkle_tree_check_read_gadget.tcc
    const size_t digest_len = HashT::get_digest_len();
    libff::alt_bn128_pp::init_public_params();
    //parameters for merkle_tree_check_read_gadget
    protoboard<FieldT> pb;
    size_t tree_depth = 16; //hardcoded to 16 --> flexible??
    //pb_linear_combination_array<FieldT> &address_bits; //& in front???
    pb_variable_array<FieldT> address_bits;
    address_bits.allocate(pb, tree_depth, "address_bits");
    //digest_variable<FieldT> leaf(pb, SHA256_digest_size, "leaf");
    digest_variable<FieldT> leaf(pb, digest_len, "leaf");
    digest_variable<FieldT> root(pb, digest_len, "root");
    merkle_authentication_path_variable<FieldT, HashT> path(pb, tree_depth, "path_var");
    //pb_linear_combination<FieldT> &read_successful;
    //std::string &annotation_prefix; //provide parameter directly: "m"

    //digest_variable<FieldT> left(pb, SHA256_digest_size, "left");
    //digest_variable<FieldT> right(pb, SHA256_digest_size, "right");
    //digest_variable<FieldT> output(pb, SHA256_digest_size, "output");

    //sha256_two_to_one_hash_gadget<FieldT> f(pb, left, right, output, "f");
    //f.generate_r1cs_constraints();
    //read_successful --> ONE
    merkle_tree_check_read_gadget<FieldT, HashT> m(pb, tree_depth, address_bits, leaf, root, path, ONE, "m");
    path.generate_r1cs_constraints();
    m.generate_r1cs_constraints();

    auto json = r1cs_to_json(pb);

    auto result = new char[json.size()];
    memcpy(result, json.c_str(), json.size() + 1);
    return result;
}

//template<typename ppT> //undefined reference to `_merkleReadWitness' [when building zokrates_cli]
char* _merkleReadWitness(const uint8_t* inputs, int inputs_length)
{
    // typedef ram_zksnark_machine_pp<ppT> ramT;
    // typedef ram_base_field<ramT> FieldT;
    // typedef CRH_with_bit_out_gadget<FieldT> HashT;

  //see test: https://github.com/scipr-lab/libsnark/blob/master/libsnark/gadgetlib1/gadgets/merkle_tree/merkle_tree_check_read_gadget.tcc
    const size_t digest_len = HashT::get_digest_len();
    libff::alt_bn128_pp::init_public_params();
    //parameters for merkle_tree_check_read_gadget
    protoboard<FieldT> pb;
    size_t tree_depth = 16; //hardcoded to 16 --> flexible??
    pb_variable_array<FieldT> address_bits;
    address_bits.allocate(pb, tree_depth, "address_bits");
    digest_variable<FieldT> leaf(pb, digest_len, "leaf");
    digest_variable<FieldT> root(pb, digest_len, "root");
    merkle_authentication_path_variable<FieldT, HashT> path(pb, tree_depth, "path_var");

    //read_successful --> ONE
    merkle_tree_check_read_gadget<FieldT, HashT> m(pb, tree_depth, address_bits, leaf, root, path, ONE, "m");
    //path.generate_r1cs_constraints(true);
    path.generate_r1cs_constraints();
    //m.generate_r1cs_constraints(true);
    m.generate_r1cs_constraints();

//leaf aka ri or di
//address aka pathToLeaf
//path aka rjVec or djVec (other nodes)
//root aka rRoot or dRoot
    libff::bit_vector leafInput;
    size_t addressInput;
    std::vector<merkle_authentication_node> pathInput(tree_depth);
    libff::bit_vector rootInput;

//fill witness input variables with inputs (parameter)

  // for (int i = 0; i < inputs_length / 2; i++) {
  //     left_bv.push_back(libsnarkBigintFromBytesAux(inputs + i*32) == 1);
  // }
// for (int i = inputs_length / 2; i < inputs_length; i++) {
//     right_bv.push_back(libsnarkBigintFromBytesAux(inputs + i*32) == 1);
// }

    leaf.generate_r1cs_witness(leafInput);
    path.generate_r1cs_witness(addressInput, pathInput);
    m.generate_r1cs_witness();
    root.generate_r1cs_witness(rootInput);

    assert(pb.is_satisfied());

    auto json = array_to_json(pb);
    auto result = new char[json.size()];
    memcpy(result, json.c_str(), json.size() + 1);
    return result;
}
