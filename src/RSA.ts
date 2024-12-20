console.log("====================================");
console.log("Rivest-Shamir-Adleman (RSA) Algorithm");
console.log("====================================");

const p = 61;
const q = 53;
const n = p * q;  
const e = 17;
const d = 2753;

// Convert each character to its ASCII value for encryption
const encrypt = (message: string, e: number, n: number) => {
  return message.split('').map(char => BigInt(char.charCodeAt(0)) ** BigInt(e) % BigInt(n));
}

// Convert each number back to its character after decryption
const decrypt = (cipher: bigint[], d: number, n: number) => {
  return cipher.map(num => String.fromCharCode(Number((num ** BigInt(d) % BigInt(n))))).join('');
}

// Convert the string message to an array of numbers
const message = "HELLO-WORLD";

const encryptedMessage = encrypt(message, e, n);
const decryptedMessage = decrypt(encryptedMessage, d, n);

console.log("Message:", message);
console.log("Encrypted message:", encryptedMessage);
console.log("Decrypted message:", decryptedMessage);