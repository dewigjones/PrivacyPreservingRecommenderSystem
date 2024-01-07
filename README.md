# Privacy Preserving Recommender System
## Overview
This is a Privacy Preserving Recommender System for movie recommendations using the Netflix Prize Dataset. It is based on:

> Jinsu Kim, Dongyoung Koo, Yuna Kim, Hyunsoo Yoon, Junbum Shin, and Sungwook Kim. 2018. Efficient Privacy-Preserving Matrix Factorization for Recommendation via Fully Homomorphic Encryption. ACM Trans. Priv. Secur. 21, 4, Article 17 (November 2018), 30 pages. https://doi.org/10.1145/3212509 
## Installation
This is a work in progress and not operational yet. In order to get the project up and running to its current state, make sure CMAKE is installed and run:
    
    git submodule init
    git submodule update
    ./vcpkg/vcpkg integrate install
    mkdir build
    cd build
    cmake ..
    build
    ./PPRS