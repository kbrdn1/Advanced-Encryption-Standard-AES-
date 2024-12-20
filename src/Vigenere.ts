console.log("====================================");
console.log("Chiffrement de Vigenère");
console.log("====================================");

// Instruction
// Chiffrez le texte suivant avec la clé "CRYPTO" en utilisant le chiffrement de Vigenère

const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

const text = "CRYPTOGRAPHIE";

const key = "cm4s6i8bs000143lvkt8iazit";

const subAlphabet = (key: string) => {
  let subAlphabet = "";
  for (let i = 0; i < alphabet.length; i++) {
    subAlphabet += alphabet[(i + alphabet.indexOf(key[i % key.length])) % alphabet.length];
  }
  return subAlphabet;
}

const vigenere = (text: string, key: string) => {
  const subAlphabetKey = subAlphabet(key);
  let result = "";
  for (let i = 0; i < text.length; i++) {
    result += subAlphabetKey[alphabet.indexOf(text[i])];
  }
  return result;
}

console.log(vigenere(text, key)); // DZSJJZJXZJZ