cmake_minimum_required (VERSION 2.6)
project (ConnectionSample) 

add_executable (sampler src/MurmurHash2.cc src/bloom.cc src/sampler.cc) 
target_link_libraries (sampler pcap)

