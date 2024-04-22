"""
Functional Programming Overview:

Functional programming (FP) is a paradigm that treats computation as the evaluation of mathematical functions. It emphasizes the use of immutable data, pure functions without side effects, and the application of higher-order functions.

Pros:
- Predictability and Simplicity: Pure functions make the code easier to understand, debug, and test since outputs depend only on inputs, without hidden states or side effects.
- Concurrency: Immutability simplifies concurrent programming by avoiding issues like race conditions.
- Reusability and Modularity: Higher-order functions and function composition can lead to more modular and reusable code.

Cons:
- Learning Curve: FP concepts can be abstract and differ significantly from imperative programming, posing a learning challenge.
- Performance: Immutable data structures can sometimes lead to performance overheads due to the need to create new objects instead of modifying existing ones.
- Verbosity: Certain tasks may require more code than in imperative paradigms, potentially leading to verbosity.

1. **Immutability**: FP emphasizes the use of immutable data structures, which can prevent a wide range of security issues related to unexpected data mutation. In cryptographic algorithms like DES, ensuring that key components (such as keys, plaintext, and ciphertext) remain unchanged throughout execution can help prevent subtle bugs that might lead to vulnerabilities.

2. **Pure Functions**: The core of FP, pure functions, have no side effects and always produce the same output for the same input. This predictability makes code easier to audit for security vulnerabilities and ensures that functions can be isolated and tested for correctness without worrying about external state. In the context of DES, using pure functions for operations like permutation, substitution, and key generation can simplify the verification of these critical steps.

3. **Higher-Order Functions and Composition**: FP allows for the creation of higher-order functions and encourages function composition, enabling a more modular design. By decomposing complex operations into smaller, composable functions, developers can more easily reason about individual components' security. This modular approach also facilitates code reuse, reducing the likelihood of introducing new vulnerabilities through duplication of effort.

4. **Concurrency and Parallelism**: FP's emphasis on immutability and statelessness naturally lends itself to concurrent and parallel execution. In security applications where performance and responsiveness are crucial (such as real-time encryption/decryption), FP can enable efficient parallel processing without the common concurrency pitfalls (e.g., race conditions) that can lead to security vulnerabilities.

5. **Formal Verification**: The principles of FP are closely aligned with mathematical functions, making FP-based programs more amenable to formal verification techniques. In the context of cryptographic algorithms, where mathematical correctness is paramount, FP can facilitate the formal verification of algorithm implementations against their specifications, ensuring their security properties are preserved.

In summary, adopting functional programming principles in the implementation of DES and other cryptographic algorithms can lead to more secure, maintainable, and robust software. By leveraging immutability, pure functions, function composition, and the advantages of FP in concurrency, developers can create cryptographic software that is both efficient and secure.

This code demonstrates the application of FP principles in the context of encryption algorithms, showcasing how these concepts can enhance security programming through clarity and modularity.
"""

from tables import *

def expansion_function(block):
    # Using list comprehension for a more functional approach
    return ''.join(block[i - 1] for i in ExpTable)

def permutation(block):
    return ''.join(block[i - 1] for i in PermTables)

# Pure functions do not depend or alter any exisiting state
def apply_s_boxes(expanded_block):
    def apply_s_box(section, s_box):
        row = int(section[0] + section[5], 2)
        col = int(section[1:5], 2)
        return format(SBoxes[s_box][row][col], '04b')

    # Splitting into sections and applying the S-Box using map
    sections = [expanded_block[i * 6:(i + 1) * 6] for i in range(8)]
    output_bits = map(apply_s_box, sections, range(8))
    return ''.join(output_bits)

# returns a new string and does not edit an exisiting one
# This allows us to protect against bugs that arise from mutable states
def permute(block, table):
    return ''.join(block[i - 1] for i in table)

# returns a new string and does not edit an exisiting one
def left_shift(block, shifts):
    return block[shifts:] + block[:shifts]

def generate_subkeys(key):
    key_bin = bin(int(key, 16))[2:].zfill(64)
    key_plus = permute(key_bin, PC1)  # PC1 to get a 56-bit key

    # Splitting the key_plus into two halves
    C, D = key_plus[:28], key_plus[28:]

    subkeys = []
    for shift in ShiftSchedule:
        # Perform the shift operation
        C, D = left_shift(C, shift), left_shift(D, shift)

        # Combine C and D for PC2 permutation to generate a subkey
        subkey = permute(C + D, PC2)  # Ensure C+D is 56 bits and PC2 picks 48 bits out of it
        subkeys.append(subkey)

    return subkeys

# Pure functions do not depend or alter any exisiting state
def xor(bits1, bits2):
    # Using zip in a list comprehension for a functional style
    return ''.join(str(int(b1) ^ int(b2)) for b1, b2 in zip(bits1, bits2))


# Pure functions do not depend or alter any exisiting state
def DES_round(left, right, key):
    # Keeping the function pure by not mutating inputs and using the results of pure functions
    expanded_right = expansion_function(right)
    temp = xor(expanded_right, key)
    substituted = apply_s_boxes(temp)
    permuted = permutation(substituted)
    new_right = xor(left, permuted)
    return right, new_right

def DES_encrypt(plaintext, key):
    bin_plaintext = bin(int(plaintext, 16))[2:].zfill(64)
    permuted_plaintext = permute(bin_plaintext, Perm1)
    L, R = permuted_plaintext[:32], permuted_plaintext[32:]

    subkeys = generate_subkeys(key)

    for round_key in subkeys:
        L, R = DES_round(L, R, round_key)

    combined_text = R + L
    encrypted_bin = permute(combined_text, LastPerm)
    ciphertext = hex(int(encrypted_bin, 2))[2:].upper().zfill(16)
    return ciphertext

def DES_decrypt(ciphertext, key):
    bin_ciphertext = bin(int(ciphertext, 16))[2:].zfill(64)
    permuted_ciphertext = permute(bin_ciphertext, LastPerm)
    L, R = permuted_ciphertext[:32], permuted_ciphertext[32:]

    subkeys = generate_subkeys(key)
    subkeys.reverse()

    for round_key in subkeys:
        R, L = DES_round(R, L, round_key)

    combined_text = L + R
    decrypted_bin = permute(combined_text, Perm1)
    plaintext = hex(int(decrypted_bin, 2))[2:].upper().zfill(16)
    return plaintext

def extended_gcd(aa, bb):
    def loop(a, b, x0, x1, y0, y1):
        if b == 0:
            return a, x0, y0
        else:
            q = a // b
            return loop(b, a % b, x1, x0 - q * x1, y1, y0 - q * y1)

    gcd, x, y = loop(aa, bb, 1, 0, 0, 1)
    return gcd, x * (-1 if aa < 0 else 1), y * (-1 if bb < 0 else 1)

def modinv(e, phi):
    gcd, x, _ = extended_gcd(e, phi)
    if gcd == 1:
        return x % phi
    else:
        raise Exception('Modular inverse does not exist')

def rsa_encrypt(x, e, n):
    return pow(x, e, n)

def rsa_decrypt(c, d, n):
    return pow(c, d, n)

def main():
    plaintext = "123454321FEDCBA"
    key = "873625123ACDCFE2"
    ciphertext = DES_encrypt(plaintext, key)
    print("plaintext", plaintext)
    print("Key ", key)
    print(f"Ciphertext: {ciphertext}")
    # q1
    ciphertext = "85E813540F0AB405"
    key = "133457799BBCDFF1"
    plaintext = DES_decrypt(ciphertext, key)
    print("Ciphertext:", ciphertext)
    print("Key:", key)
    print(f"Decrypted plaintext: {plaintext}")
    #RSA q2
    p = 3
    q = 11
    e = 7
    phi_n = (p - 1) * (q - 1)
    n = p * q
    d = modinv(e, phi_n)
    plaintext = 5
    ciphertext = rsa_encrypt(plaintext, e, n)
    decrypted_plaintext = rsa_decrypt(ciphertext, d, n)
    print(f"Original plaintext: {plaintext}")
    print(f"Encrypted ciphertext: {ciphertext}")
    print(f"Decrypted plaintext: {decrypted_plaintext}")

    # q3
    p = 61
    q = 53
    n = p * q
    phi_n = (p - 1) * (q - 1)
    e = 17
    d = modinv(e, phi_n)
    plaintext = 217
    ciphertext = rsa_encrypt(plaintext, e, n)
    decrypted_plaintext = rsa_decrypt(ciphertext, d, n)

    print(f"Public Key: (e={e}, n={n})")
    print(f"Private Key: (d={d}, n={n})")
    print(f"Plaintext: {plaintext}")
    print(f"Encrypted: {ciphertext}")
    print(f"Decrypted: {decrypted_plaintext}")

if __name__ == "__main__":
    main()
