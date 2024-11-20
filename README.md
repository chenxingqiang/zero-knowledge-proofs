# Awesome Zero Knowledge Proofs (ZKP) Resources

Curated by [chenxingqiang](https://github.com/chenxingqiang)

## Table of Contents

- [General Introduction](#general-introduction)
- [Courses and Tutorials](#courses-and-tutorials)
- [Programming Languages & Tools](#programming-languages--tools)
- [Proof Systems Comparison](#proof-systems-comparison)
- [Major Proof Systems](#major-proof-systems)
- [Applications](#applications)
- [Communities & Social Media](#communities--social-media)

## General Introduction

### Basic Concepts
- [Zero Knowledge Proofs: An Illustrated Primer](https://blog.cryptographyengineering.com/2014/11/27/zero-knowledge-proofs-illustrated-primer/) by Matthew Green
- [ZK Basics Cheatsheet](https://github.com/ventali/awesome-zk/ZK-Basics-Cheatsheet.md) - A "for (not too much) dummies" poster
- [A Non-Mathematical Introduction to Zero Knowledge Proof](https://github.com/ventali/awesome-zk/non-mathematical-introduction.md)

### ZK Whiteboard Sessions by ZK Hack
1. What is a SNARK?
2. Building a SNARK (Part 1)
3. Building a SNARK (Part 2)
4. SNARKS vs. STARKS
5. PLONK and Custom Gates
6. Lookup Arguments for Performance Optimisation
7. Zero Knowledge Virtual Machines (zkVM)
8. Achieving Decentralised Private Computation
9. Introduction to zkRollups

### Hands-On Tutorial Series
- [A Hands-On Tutorial for Zero-Knowledge Proofs](https://github.com/starkware-industries/stark-tutorial) by Shir Peled (StarkWare)
- [Zero-Knowledge Proofs for Engineers](https://www.zkproof.org/2020/03/16/zkproof-standards-workshop-4/) (Dark Forest)

## Courses and Tutorials

### Academic Courses
- [The 9th BIU Winter School on Cryptography: Zero Knowledge](https://cyber.biu.ac.il/event/the-9th-biu-winter-school-on-cryptography/)
- [UIUC: Applied Cryptography](https://courses.grainger.illinois.edu/ece498ac/sp2019/)
- [MIT IAP 2023: Modern Zero Knowledge Cryptography](https://mit-public-courses-iap-2023.github.io/6.S096/)

### Interactive Learning
- [zk Battleship](https://github.com/battleship-zk/battleship) - Interactive course by sCrypt
- [Circom and Snarkjs Tutorial](https://github.com/iden3/circom)
- [0xPARC Learning Resources](https://0xparc.org/learning)

## Programming Languages & Tools

### Languages
| Name | Type | GitHub | Documentation |
|------|------|--------|---------------|
| ZoKrates | Python subset | [Repo](https://github.com/Zokrates/ZoKrates) | [Docs](https://zokrates.github.io) |
| Circom | HDL | [Repo](https://github.com/iden3/circom) | [Docs](https://docs.circom.io) |
| SnarkyJS | TypeScript DSL | [Repo](https://github.com/o1-labs/snarkyjs) | [Docs](https://docs.minaprotocol.com/en/zkapps/snarkyjs-reference) |
| Cairo | STARK | [Repo](https://github.com/starkware-libs/cairo-lang) | [Docs](https://cairo-lang.org/docs/) |
| Leo | Functional | [Repo](https://github.com/AleoHQ/leo) | [Docs](https://developer.aleo.org/developer/language/layout/) |

### Major Tools
- ZoKrates: Toolbox for zkSNARKs
- Snarkjs: JavaScript & WASM implementation
- libsnark: C++ library
- ethsnarks: Toolkit for Ethereum
- gnark: Go library

## Proof Systems Comparison

### Key Metrics Comparison

| Feature | SNARKs | STARKs | Bulletproofs |
|---------|---------|---------|--------------|
| Proving Time | O(N * log(N)) | O(N * poly-log(N)) | O(N * log(N)) |
| Verification Time | ~O(1) | O(poly-log(N)) | O(N) |
| Proof Size | ~O(1) | O(poly-log(N)) | O(log(N)) |
| Trusted Setup | Required | Not Required | Not Required |
| Post-quantum Security | No | Yes | No |

## Major Proof Systems

### SNARKs
- Groth16
- PLONK
- Marlin
- Sonic

### STARKs
- FRI-STARKs
- SuperSonic
- Fractal

### Other Systems
- Bulletproofs
- SNORKs

## Applications

### Blockchain Applications
- Privacy Coins:
  - Zcash (SNARKs)
  - Monero (Bulletproofs)
  - Mina Protocol (Recursive SNARKs)
  - Namada (SNARKs)
  
### Non-blockchain Applications
- Machine Learning & AI:
  - zkML (Zero-Knowledge Machine Learning)
  - zk-MNIST
  - zkCNN
- Identity & Authentication:
  - Proof of Passport
  - Semaphore
  - ZK Identity Systems
- Gaming:
  - Dark Forest
  - Zordle
  - zkAutoChess
- Financial:
  - Private Auctions
  - Blind Bidding Systems
  - Token Systems

## Communities & Social Media

- [Zero Knowledge Podcast](https://zeroknowledge.fm/)
- [ZKProof](https://zkproof.org/)
- [0xPARC](https://0xparc.org/)
- [Awesome Zero Knowledge Twitter List](https://twitter.com/i/lists/1471426262552109059)

## Additional Resources

### Books
- [Proofs, Arguments, and Zero-Knowledge](https://people.cs.georgetown.edu/jthaler/ProofsArgsAndZK.pdf) by Justin Thaler
- [The MoonMath Manual to zk-SNARKs](https://github.com/ZKProofs/moonmath-manual)
- [A Graduate Course in Applied Cryptography](https://toc.cryptobook.us/) by Dan Boneh and Victor Shoup

### Performance Benchmarks
- [🏋️‍♀️ ZK Bench](https://github.com/nullchinchilla/zkbench) - Open source benchmarks for ZK implementations

# Zero Knowledge Proof Systems Comparison

*Notes: d: depth of circuit, h: width of subcircuits, c: number of copies of subcircuits, i: size of instance, w: size of witness, n: number of gates. All complexity is asymptotic*

| ZKP name | Implementation/library | Prover Runtime | Verifier Runtime | CRS/SRS size | Proof size | Post Quantum Secure? | Universal? | Trusted Setup? | Updatable? | Crypto Assumptions |
|----------|----------------------|----------------|------------------|--------------|------------|-------------------|------------|---------------|------------|-------------------|
| SNARKs | libsnarkjn (C++) | nlogn | n | n | 1 | NO | NO | YES | NO | Knowledge of Exponent (q-type) |
| Groth 2016 | bellman (in Rust) | nlogn | i | n | 1 (only 3 group elements) | NO | NO | YES | NO | Knowledge of Exponent (q-type) |
| Hyrax 2017 | hyrax2K (in C++) | d(n+clog(c))+w | i+d(h+log(h+c)) | sqrt(w) | dlog(h+c)+sqrt(w) | NO | YES | NO | NO | Discrete Log |
| ZK vSQL 2017 | N/A | nlog(c) | log(n) | log(n) | d*log(c) | NO | YES | NO | YES | Knowledge of Exponent (q-type) |
| Ligero 2017 | libiop (in C++) | nlog(n) | c*log(c)+h*log*(h) | N/A | sqrt(n) | possible, no security proof | YES | NO | NO | hash function |
| Bulletproofs 2017 | dalek (in Rust) | nlogn | nlogn | n | logn | NO | YES | NO | NO | Discrete Log |
| BCC+2017 | N/A | n | n | N/A | sqrt(n) | possible, no security proof | YES | NO | NO | hash function |
| BBC+2018 | N/A | nlogn | n | sqrt(n) | sqrt(nlogn) | possible, no security proof | YES | NO | NO | SIS |
| STARKs 2018 | libSTARK (in C++) | n*polylog(n) | polylog(n) | N/A | (logn)^2 | possible, no security proof | YES | NO | NO | hash function |
| Aurora 2018 | libiop (in C++) | nlog(n) | n | sqrt(n) | (logn)^2 | possible, no security proof | YES | NO | NO | hash function |
| GKM+2018 | N/A (the previous version of Sonic) | nlogn | i | n^2 | 1 | NO | YES | NO | YES | Knowledge of Exponent (q-type) |
| Sonic 2019 | sonic (in Rust) | nlogn | i+logn | n | 1 | NO | YES | NO | YES | AGM (algebraic group model) |
| Fractal 19 | libiop (in C++) | nlogn | i+logn | n | 1 | NO | YES | NO | YES | AGM (algebraic group model) |
| Libra 2019 (not facebook libra) | N/A (has implementation but not open-source) | n | dlogn | n | dlogn | NO | YES | YES | NO | Knowledge of Exponent (q-type) |
| PLONK 2019 (based on Sonic) | plonk (not implemented by paper authors) | nlogn | i | n | 1 | NO | YES | NO | YES | AGM (algebraic group model) |
| MARLIN 2019 (Concurrent Work of PLONK) | marlin (in Rust) | nlogn | i+logn | n | 1 | NO | YES | NO | YES | AGM (algebraic group model) |

## Important Research Lines
There are basically two important lines of research:
1. Groth 16 -> GKM+18 -> Sonic 19 -> PLONK 19 -> MARLIN 19
2. Ligero 17 -> Aurora 18 -> Fractal 19, which are IOP-based ZKP

*Note: Other works are kind of independent. We should focus on the first line and try the implementation of Groth 16, Sonic 19 and Marlin 19.*

*Source: 知乎 @koala1992*
