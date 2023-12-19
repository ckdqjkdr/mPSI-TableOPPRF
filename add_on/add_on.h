#include <vector>
#include "util.h"
#include "Common/Defines.h"

// for my unit test, works in both release and debug mode.
#define my_test_assert(expression) \
    if(!(expression)) { \
        std::cerr << "Assertion failed: " #expression \
                  << ", in file " << __FILE__ \
                  << ", line " << __LINE__ << "." << std::endl; \
        throw std::runtime_error("Assertion failed."); \
    }

void read_input_file(std::string inputfile, std::vector<osuCrypto::block> &myInputs);
void write_output_file(std::string outputfile, std::vector<osuCrypto::block> &myOutputs);