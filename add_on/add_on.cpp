#include <string>
#include <iostream>
#include <fstream>
#include "add_on.h"

void read_input_file(std::string inputfile, std::vector<osuCrypto::block> &myInputs){
    std::ifstream myfile;
    osuCrypto::u64 input_h, input_l;
    myfile.open(inputfile);
    while(myfile >> input_h >>input_l) {
        osuCrypto::block tmp = osuCrypto::toBlock(input_h, input_l);
        myInputs.push_back(std::move(tmp));
    }
    std::cout << "Add-on readfile: " << myInputs.size() << "inputs read." << std::endl;
    myfile.close();
}

void write_output_file(std::string outputfile, std::vector<osuCrypto::block> &myOutputs){
    std::ofstream myfile;
    osuCrypto::u64 output_h, output_l;
    myfile.open(outputfile);
    for(size_t i=0; i<myOutputs.size(); i++){
        output_l = (myOutputs.at(i))[0];
        output_h = (myOutputs.at(i))[1];
        myfile << output_h << " " << output_l << std::endl;
    }
    std::cout <<"Add-on writefile: " <<  myOutputs.size() << "outputs write." << std::endl;
    myfile.close();
}

