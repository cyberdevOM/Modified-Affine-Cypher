# Affine Cipher with English to Non-English character mapping
class ModifiedAffineCipher:
    def __init__(self, a, b):
        self.a = a  # Multiplicative key
        self.b = b  # Additive key
        self.m = 95  # Size of the custom alphabet (must match the mapping size)
        self.mapping = self.create_mapping()  # English to Non-English mapping
        self.inverse_mapping = {v: k for k, v in self.mapping.items()}  # Reverse mapping for decryption
        self.a_inverse = self.modular_inverse(a, self.m)  # Modular inverse of a under modulo m

    def create_mapping(self):
        # Define a dictionary mapping English characters to Non-English characters
        keyboard_chars = (
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
            "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~ "
        )

        print (len(keyboard_chars))
        non_english_chars = (
            "ÄÖÜäöüßÀÈÌÒÙÇÑáéíóúçñ¡¿§¤¥¦¬¯±²³´µ¶·¸¹º¼½¾¿×÷€£¥©®™°†‡‰‹›«»±≠≤≥∞∂∑∏∫√∇≈≡∝∅∈∉∋∌∧∨∩∪⊂⊃⊆⊇⊕⊗⊥⊨⊩⊪⊫⊬⊭"
        )

        print (len(non_english_chars))

        if len(keyboard_chars) != len(non_english_chars):
            raise ValueError("Keyboard and non-English character sets must have the same length.")
        return {keyboard_chars[i]: non_english_chars[i] for i in range(len(keyboard_chars))}


    def modular_inverse(self, a, m):
        # Find modular inverse of a under modulo m
        for x in range(1, m):
            if (a * x) % m == 1:
                return x
        raise ValueError("Multiplicative key 'a' has no modular inverse under modulo m.")

    def encrypt(self, plaintext):
        # Replace English characters with their Non-English equivalents
        mapped_plaintext = ''.join(self.mapping.get(char, char) for char in plaintext)
        ciphertext = ""  # Initialize empty ciphertext
        for char in mapped_plaintext:  # Iterate over each character in the mapped plaintext
            if char in self.inverse_mapping:  # Check if the character is in the Non-English mapping
                x = list(self.mapping.values()).index(char)  # Get the index of the Non-English character
                encrypted_value = (self.a * x + self.b) % self.m  # Apply the affine transformation
                ciphertext += list(self.mapping.values())[encrypted_value]  # Map back to a Non-English character
            else:
                ciphertext += char  # Keep non-mapped characters as is
        return ciphertext

    def decrypt(self, ciphertext):
        plaintext = ""
        for char in ciphertext:
            if char in self.inverse_mapping:  # Check if the character is in the Non-English mapping
                y = list(self.mapping.values()).index(char)  # Get the index of the Non-English character
                decrypted_value = (self.a_inverse * (y - self.b)) % self.m  # Apply the inverse affine transformation
                decrypted_char = list(self.mapping.values())[decrypted_value]  # Map back to a Non-English character
                plaintext += self.inverse_mapping[decrypted_char]  # Map to the original English character
            else:
                plaintext += char  # Keep non-mapped characters as is
        return plaintext


# Example usage
if __name__ == "__main__":
    # Define keys (a must be coprime with m)
    a = 7
    b = 3

    cipher = ModifiedAffineCipher(a, b)

    # Input message
    message = "THiS isA Test Message+*()"
    print("Original Message:", message)

    # Encrypt the message
    encrypted_message = cipher.encrypt(message)
    print("Encrypted Message:", encrypted_message)

    # Decrypt the message
    decrypted_message = cipher.decrypt(encrypted_message)
    print("Decrypted Message:", decrypted_message)