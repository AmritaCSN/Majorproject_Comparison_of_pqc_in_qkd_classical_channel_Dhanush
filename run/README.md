# Kyber

Kyber is Post Quantum Cryptography algorithm.It is a public key algorithm. Kyber has been integrated in QKD Classical channel for the Encryption and Decryption of data.

# Falcon

Falcon is a Post Quantum -Digital Signature Algorithm.It is integrated in Quantum Key distribution Classical channel for Authentication.

# How to run?

### Install Python 3.x

You should have Python 3.x installed on your system.

```
sudo apt-get install python3
```

### Install dependencies

You should have [SymPy](http://www.sympy.org), [NumPy](http://www.numpy.org/) and [docopt](http://www.docopt.org/) package installed.

```
pip3 install --user sympy
pip3 install --user numpy
pip3 install --user docopt
```

## How to use it?

To Run the code execute `bb84_Kyber.py` file

```python3 bb84_Kyber.py
python3 bb84_Kyber.py
```

## **Security Analysis**

To Check the Security Analysis of the Algorithm `Kyber_Entropy_correlation.py` file

Following Security Analysis is mesured for the algorithm

1. Information Entropy Analysis
2. Correlation Coefficent Analysis
3. Key Sensitivity Analysis

```python3 Kyber_Entropy_correlation.py
python3 Kyber_Entropy_correlation.py
python3 bb84_encrypt_security_key_analysis.py
```

## **Performance Analysis**

To check the performance Runtime at different phases has been calculated such as

1. Encryption Time
2. Decryption Time
3. Signing Time
4. Verification Time
5. Total Runtime

```python3 bb84_Kyber_Performance.py
python3 bb84_Kyber_Performance.py
```
