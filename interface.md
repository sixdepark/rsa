# RSA Project Interface

## 1. Project files

- `rsa_core.py`: shared RSA key generation, integer encryption, and decryption.
- `rsa_basic.py`: standalone introductory RSA demonstration.
- `example_usage.py`: example using the shared RSA module.
- `fermat_attack.py`: Fermat factorization implementation and demonstration.
- `fermat_experiment.py`: Fermat parameter experiment.
- `fermat_large_experiment.py`: teammate's 1024/2048-bit Fermat experiments.
- `wiener_attack.py`: Wiener attack implementation.
- `wiener_demo.py`: live demonstration using an intentionally weak RSA key.
- `wiener_large_demo.py`: presentation-ready attack against a fixed RSA-2048 key.
- `generate_wiener_demo_fixture.py`: one-time preparation of the public demo data.
- `wiener_experiment.py`: reproducible small and 512/1024/2048-bit experiments.
- `wiener_presentation_graphs.py`: presentation-ready graphs from measured data.
- `test_wiener_attack.py`: automated Wiener attack tests.
- `requirements.txt`: SymPy, PyCryptodome, and Matplotlib dependencies.
- `results/`: CSV output from the attack experiments.

The project requires Python 3.10 or later. Install experiment dependencies with:

```text
python -m pip install -r requirements.txt
```

SymPy supports the teammate's large Fermat key generation, PyCryptodome
generates the large Wiener primes, and Matplotlib generates the graphs. The
attack implementations themselves remain dependency-free.

## 2. Shared RSA functions

### `generate_keypair(p, q, e=65537)`

Generates RSA parameters from two distinct primes. The public exponent must
satisfy `1 < e < phi` and `gcd(e, phi) = 1`. The returned dictionary contains
`p`, `q`, `n`, `phi`, `e`, and `d`.

Example:

```python
key = generate_keypair(p=61, q=53, e=17)
n = key["n"]
d = key["d"]
```

### `encrypt(message, e, n)`

Encrypts an integer satisfying `0 <= message < n` with the public key.

### `decrypt(ciphertext, d, n)`

Decrypts an integer satisfying `0 <= ciphertext < n` with the private key.

Invalid arguments raise `ValueError`.

## 3. Fermat factorization attack

`fermat_factor(n, max_checks=100000)` in `fermat_attack.py` factors an odd
modulus when its two prime factors are sufficiently close. It uses only the
public modulus `n`. It returns `(p, q, checks)` on success and `None` if the
configured check limit is reached.

Run the Fermat demonstration and experiments with:

```text
python fermat_attack.py
python fermat_experiment.py
python fermat_large_experiment.py
```

The small experiment writes `results/fermat_results.csv`. The teammate's large
experiment generates three 1024-bit and three 2048-bit intentionally weak
moduli with adjacent primes, verifies recovered factors, private keys, and
plaintexts, and writes `results/fermat_large_results.csv`. Its key generation
uses SymPy; Fermat factorization itself still receives only the public modulus.

## 4. Wiener attack

Wiener's attack targets a different RSA weakness: an unusually small private
exponent `d`. It approximates `e/n` with continued-fraction convergents. For a
vulnerable key, one convergent is `k/d`, where `e*d - 1 = k*phi(n)`. A candidate
is accepted only when the resulting quadratic equation has integer roots whose
product is exactly `n`.

### `wiener_attack(e, n)`

Uses only the public parameters `e` and `n`. It returns the recovered private
exponent `d` or `None` when the attack is unsuccessful. Invalid inputs raise
`TypeError` or `ValueError`.

### `recover_private_key(e, n)`

Runs the same attack but returns a dictionary containing `d`, `p`, `q`, `phi`,
and `k`. It returns `None` on failure. This form is useful for mathematical
verification and automated tests.

### Mathematical helpers

- `continued_fraction(numerator, denominator)` returns the continued-fraction
  terms using exact integer arithmetic.
- `convergents(terms)` yields numerator/denominator pairs.

Run the demonstration, full experiment, and tests with:

```text
python wiener_demo.py
python wiener_experiment.py
python -m unittest -v test_wiener_attack.py
```

The full experiment keeps the original small cases and then tests 512-, 1024-,
and 2048-bit RSA. Its defaults are five independent moduli per size/profile and
five attack timing repetitions per key. The deterministic seed is for
repeatability only; it must not be used to generate real RSA keys.

Useful experiment options are:

```text
python wiener_experiment.py --small-only
python wiener_experiment.py --large-only
python wiener_experiment.py --samples 5 --timing-repeats 5 --seed 6104
```

Each large modulus is constructed from distinct, equally sized PyCryptodome
primes. The program verifies the requested modulus length, balanced primes,
`gcd(d, phi) = 1`, and `e*d mod phi = 1` before running the attack. Key
generation is timed separately and is never included in the attack time.

Five private-exponent profiles are measured:

- `very_small`: approximately `n^(1/8)`, comfortably below the Wiener bound.
- `below_bound`: approximately `0.8` times the classical bound.
- `at_bound`: approximately the classical bound.
- `above_bound`: approximately `1.2` times the classical bound.
- `normal_control`: the large `d` produced by the standard public exponent
  `e = 65537`.

The classical result gives a sufficient condition near
`d < n^(1/4) / 3` for balanced primes. It is not an exact failure boundary, so
the experiment records rather than assumes the outcome at and above the bound.

### Experiment outputs

- `results/wiener_results.csv`: original small-key cases.
- `results/wiener_large_results.csv`: all individual large-key trials.
- `results/wiener_large_summary.csv`: success rates and median measurements.
- `results/wiener_success_rate.png`: success rate against private-exponent bits.
- `results/wiener_execution_time.png`: attack time against RSA modulus bits.
- `results/wiener_success_rate_ppt.png`: grouped presentation success-rate chart.
- `results/wiener_execution_time_ppt.png`: near-bound presentation timing chart.

### Recorded results (seed 6104)

The completed run tested 75 large-key cases. Every profile from `very_small`
through `above_bound` recovered the exact `d`, `p`, and `q` in all 5/5 keys at
each modulus size. Every `normal_control` case failed to recover a key (0/5), as
expected for this data set. This above-bound success demonstrates why the
classical bound must be described as sufficient rather than as an exact cutoff.

Median attack times for the `at_bound` profile were 0.3030 ms at 512 bits,
0.7788 ms at 1024 bits, and 3.1034 ms at 2048 bits. Median prime-pair generation
times were 58.6113 ms, 266.2141 ms, and 535.6874 ms respectively. Exact results
and the other profiles are stored in `wiener_large_summary.csv`.

## 5. RSA-2048 Wiener live demonstration

`wiener_large_demo.py` demonstrates that modulus length alone does not make an
RSA key safe. It attacks an intentionally vulnerable 2048-bit modulus whose
private exponent is only 508 bits and is approximately one eighth of the
classical Wiener bound. This is not a normally generated secure RSA-2048 key.

The live demo loads `results/wiener_demo_public.json`. The fixture contains only
the public exponent `e`, modulus `n`, test ciphertext, expected plaintext, and
descriptive metadata. It does not contain the original private exponent or
prime factors. The live attack calls `recover_private_key(e, n)`, so the
continued-fraction attack receives public RSA parameters only.

Run the live demo from the project directory:

```text
python wiener_large_demo.py
```

The output shows a 2048-bit modulus, shortened public values, completion of the
continued-fraction analysis, recovery of `d`, recovery of two 1024-bit factors,
RSA key-equation verification, successful decryption of message `42`, measured
attack time, and `RESULT: PASS`. On the recorded validation runs, the attack
took approximately 2.76 to 3.34 milliseconds.

### One-time fixture preparation

The checked-in fixture is already prepared; key generation is not part of the
live presentation. To intentionally replace it, install `requirements.txt` and
run:

```text
python generate_wiener_demo_fixture.py --force
```

The setup script uses PyCryptodome to generate distinct balanced 1024-bit
primes until their product is exactly 2048 bits. It chooses `d` below
`n^(1/4)/3`, computes `e`, encrypts the test message, and runs the real attack.
Before saving public data, it verifies that the recovered `d`, `p`, and `q`
exactly match the generation-time secrets and that decryption succeeds. The
original private values are then omitted from the JSON fixture.

## 6. Difference between the attacks

Fermat factorization exploits primes `p` and `q` that are too close together
and works directly from `n`. Wiener attack exploits a private exponent `d` that
is too small and uses both public values `e` and `n`. A key may be vulnerable to
one attack without being vulnerable to the other.

## 7. Scope and limitations

This is unpadded, integer-only educational RSA and must not protect real data.
The shared primality test uses trial division and is intended for small teaching
examples, not production key generation. The large experiment therefore uses
PyCryptodome without changing `rsa_core.py`. Classical Wiener's attack recovers
only sufficiently small `d` values under its usual balanced-prime assumptions;
returning `None` does not prove that an RSA key is secure against every attack.
Five keys per configuration are useful for a classroom demonstration but are
not enough for a statistically comprehensive cryptographic study. Timing also
depends on the Python version, operating system, CPU, and background load.
The fixed RSA-2048 fixture and message `42` are designed only for a reliable
30-60 second classroom demonstration. Textbook RSA without padding must never
be used to protect production data.
