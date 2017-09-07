Labelled Homomorphic Encryption for Quadratic Polynomials
=========================================================
                      
Author
------

Manuel Barbosa
HASLab INESC TEC and DCC FCUP
mbb@dcc.fc.up.pt

References
----------

Labeled Homomorphic Encryption: Scalable and Privacy-Preserving Processing of Outsourced Data
Manuel Barbosa, Dario Catalano and Dario Fiore
Published in ESORICS 2017
Full version available at https://eprint.iacr.org/2017/326

Dependencies
------------

Requires GNU Multiprecision Arithmetic Library (GMP) available from gmplib.org.

Build Instructions
------------------

1 - Initialize Keccak submodule: 

$ git submodule init

2 - Update Keccak submodule: 

$ git submodule update

3 - Build Keccak library for target platform

$ cd KeccakCodePackage
$ make generic64/libkeccak.a # This is an example. Faster compilation options will probably exist (requires updating CMake)

4 - Build from source

$ cd ..

$ mkdir build && cd build && cmake .. 

$ make

6 - Run the test application

$ make test

