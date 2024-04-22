from tables import *


def expansion_function(block):
    return ''.join(block[i - 1] for i in ExpTable)

def permutation(block):
    return ''.join(block[i - 1] for i in PermTables)

def apply_s_boxes(expanded_block):
    output = ''
    for i in range(8):
        section = expanded_block[i*6:(i+1)*6]

        row = int(section[0] + section[5], 2)
        col = int(section[1:5], 2)
        s_box_output = SBoxes[i][row][col]
        output += format(s_box_output, '04b')
    return output

def permute(block, table):
    return ''.join(block[i - 1] for i in table)


def left_shift(block, shifts):
    return block[shifts:] + block[:shifts]


def generate_subkeys(key):
    key_bin = bin(int(key, 16))[2:].zfill(64)
    key_plus = permute(key_bin, PC1)
    C, D = key_plus[:28], key_plus[28:]

    subkeys = []
    for shift in ShiftSchedule:
        C, D = left_shift(C, shift), left_shift(D, shift)
        subkey = permute(C + D, PC2)
        subkeys.append(subkey)
    return subkeys


def xor(bits1, bits2):
    return ''.join(str(int(b1) ^ int(b2)) for b1, b2 in zip(bits1, bits2))


def DES_round(left, right, key):
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
    last_remainder, remainder = abs(aa), abs(bb)
    x, last_x, y, last_y = 0, 1, 1, 0
    while remainder:
        last_remainder, (quotient, remainder) = remainder, divmod(last_remainder, remainder)
        x, last_x = last_x - quotient*x, x
        y, last_y = last_y - quotient*y, y
    return last_remainder, last_x * (-1 if aa < 0 else 1), last_y * (-1 if bb < 0 else 1)

def modinv(e, phi):
    gcd, x, y = extended_gcd(e, phi)
    if gcd != 1:
        raise Exception('Modular inverse does not exist')
    else:
        return x % phi

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
