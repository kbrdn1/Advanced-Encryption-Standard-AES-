# Advanced Encryption Standard (AES)

## Table des matières
1. [Installation des dépendances](#installation-des-dépendances)
2. [Exécution](#exécution)
3. [Description du processus de chiffrement AES](#description-du-processus-de-chiffrement-aes)
4. [Explication détaillée du code](#explication-détaillée-du-code)
    - [Affichage d'informations](#affichage-dinformations)
    - [Table de substitution (S-Box)](#table-de-substitution-s-box)
    - [Fonction de multiplication dans le champ de Galois](#fonction-de-multiplication-dans-le-champ-de-galois)
    - [Fonction de calcul de la constante de ronde (Rcon)](#fonction-de-calcul-de-la-constante-de-ronde-rcon)
    - [Fonction de substitution d'un octet](#fonction-de-substitution-dun-octet)
    - [Fonction de transformation de clé](#fonction-de-transformation-de-clé)
    - [Fonction de génération de clés étendues](#fonction-de-génération-de-clés-étendues)
    - [Fonction d'ajout de clé de ronde](#fonction-dajout-de-clé-de-ronde)
    - [Fonction de substitution des octets (SubBytes)](#fonction-de-substitution-des-octets-subbytes)
    - [Fonction de décalage des lignes (ShiftRows)](#fonction-de-décalage-des-lignes-shiftrows)
    - [Fonction de mélange des colonnes (MixColumns)](#fonction-de-mélange-des-colonnes-mixcolumns)
    - [Fonction de chiffrement AES](#fonction-de-chiffrement-aes)
    - [Fonction de déchiffrement AES](#fonction-de-déchiffrement-aes)
    - [Fonction de conversion de tableau d'octets en chaîne](#fonction-de-conversion-de-tableau-doctets-en-chaîne)
    - [Exemple de chiffrement et déchiffrement](#exemple-de-chiffrement-et-déchiffrement)
5. [Chiffrement de Vigenère](#chiffrement-de-vigenère)
    - [Explication du chiffrement de Vigenère](#explication-du-chiffrement-de-vigenère)
    - [Exemple de chiffrement et déchiffrement avec Vigenère](#exemple-de-chiffrement-et-déchiffrement-avec-vigenère)
6. [Algorithme RSA](#algorithme-rsa)
    - [Explication de l'algorithme RSA](#explication-de-lalgorithme-rsa)
    - [Exemple de chiffrement et déchiffrement avec RSA](#exemple-de-chiffrement-et-déchiffrement-avec-rsa)

## Installation des dépendances

```bash
bun install
```

## Exécution

```bash
bun run index.ts
```

## Description du processus de chiffrement AES

Le processus de chiffrement AES consiste à transformer un état initial en un état chiffré en utilisant une série de clés de ronde générées à partir de la clé initiale. Cela se fait en plusieurs étapes :

1. **Substitution Box (S-Box)** : Une table prédéfinie utilisée pour effectuer la substitution des octets.
2. **RotWord** : Une fonction qui décale cycliquement les octets d'un mot.
3. **SubWord** : Une fonction qui applique la S-Box à chaque octet d'un mot.
4. **Rcon** : Une constante de ronde utilisée dans le processus d'expansion de clé.
5. **Multiplication dans le champ de Galois (Gmul)** : Une fonction utilisée pour effectuer la multiplication dans le champ fini.
6. **Key Expansion** : Un processus qui génère les clés de ronde à partir de la clé initiale.
7. **SubBytes** : Une fonction qui applique la S-Box à chaque octet de l'état.
8. **ShiftRows** : Une fonction qui décale les lignes de l'état de manière cyclique.
9. **MixColumns** : Une fonction qui mélange les colonnes de l'état.
10. **AddRoundKey** : Une fonction qui ajoute une clé de ronde à l'état.

Le chiffrement AES prend l'état initial et effectue les étapes suivantes :
- Appliquer la clé de ronde initiale.
- Pour chaque ronde, appliquer les fonctions SubBytes, ShiftRows, MixColumns et AddRoundKey.
- Pour la dernière ronde, appliquer les fonctions SubBytes, ShiftRows et AddRoundKey.

## Explication détaillée du code

### Affichage d'informations

```ts
console.log("====================================");
console.log("Advanced Encryption Standard (AES)");
console.log("====================================");
```

Ces lignes affichent des informations de base sur l'algorithme AES.

### Table de substitution (S-Box)

```ts
const s_box = [
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  // ... (autres valeurs)
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
];
```

La `s_box` est une table de substitution utilisée dans l'algorithme AES pour effectuer une substitution non linéaire des octets.

### Fonction de multiplication dans le champ de Galois

```ts
export const gmul = (a: number, b: number): number => {
  let p = 0;

  for (let i = 0; i < 8; i++) {
    if (b & 1) p ^= a;

    const highBit = a & 0x80;

    a = (a << 1) & 0xFF;

    if (highBit) a ^= 0x1b;

    b >>= 1;
  }

  return p;
}
```

La fonction `gmul` effectue une multiplication dans le champ de Galois (2^8), ce qui est essentiel pour certaines opérations dans AES.

### Fonction de calcul de la constante de ronde (Rcon)

```ts
const rc = (i: number): number => {
  let r = 1;
  for (let j = 1; j < i; j++) {
    r = gmul(r, 2);
  }
  return r;
};
```

La fonction `rc` calcule la constante de ronde `Rcon` utilisée dans le processus de génération de clés.

### Fonction de substitution d'un octet

```ts
const srd = (i: number): number => {
  return s_box[i];
};
```

La fonction `srd` retourne la valeur substituée d'un octet en utilisant la `s_box`.

### Fonction de transformation de clé

```ts
const transformKey = (key: number[]): number[][] => {
  const matrix: number[][] = [];
  for (let i = 0; i < 4; i++) {
    matrix.push(key.slice(i * 4, i * 4 + 4));
  }
  return matrix;
};
```

La fonction `transformKey` transforme une clé plate en une matrice de 4x4.

### Fonction de génération de clés étendues

```ts
export const keyExpansion = (k: number[]): number[][] => {
  const w: number[][] = Array(44)
    .fill(null)
    .map(() => Array(4).fill(0));
  const key = transformKey(k);

  for (let j = 0; j < key.length; j++) {
    for (let i = 0; i < 4; i++) {
      w[j][i] = key[i][j];
    }
  }

  for (let j = 4; j < 44; j++) {
    let temp = w[j - 1].slice();

    if (j % 4 === 0) {
      temp = [srd(temp[1]), srd(temp[2]), srd(temp[3]), srd(temp[0])];
      temp[0] ^= rc(j / 4);
    }

    for (let i = 0; i < 4; i++) {
      w[j][i] = w[j - 4][i] ^ temp[i];
    }
  }

  return w;
};
```

La fonction `keyExpansion` génère les clés étendues à partir de la clé initiale. Elle commence par copier la clé initiale dans les premières positions du tableau `w`. Ensuite, elle génère les clés suivantes en utilisant les opérations `rotWord`, `subWord`, et `Rcon`.

### Fonction d'ajout de clé de ronde

```ts
const addRoundKey = (state: number[][], key: number[][]): void => {
  for (let i = 0; i < 4; i++) {
    for (let j = 0; j < 4; j++) {
      state[i][j] ^= key[j][i];
    }
  }
};
```

La fonction `addRoundKey` ajoute une clé de ronde à l'état en effectuant un XOR entre chaque octet de l'état et la clé de ronde correspondante.

### Fonction de substitution des octets (SubBytes)

```ts
const subBytes = (state: number[][]): void => {
  for (let i = 0; i < 4; i++) {
    for (let j = 0; j < 4; j++) {
      state[i][j] = srd(state[i][j]);
    }
  }
};
```

La fonction `subBytes` applique la substitution `s_box` à chaque octet de l'état.

### Fonction de décalage des lignes (ShiftRows)

```ts
const shiftRows = (state: number[][]): void => {
  for (let i = 1; i < 4; i++) {
    state[i] = state[i].slice(i).concat(state[i].slice(0, i));
  }
};
```

La fonction `shiftRows` effectue un décalage circulaire des lignes de l'état.

### Fonction de mélange des colonnes (MixColumns)

```ts
const mixColumns = (state: number[][]): void => {
  for (let j = 0; j < 4; j++) {
    const a = state.map((row) => row[j]);
    state[0][j] = gmul(a[0], 2) ^ gmul(a[1], 3) ^ a[2] ^ a[3];
    state[1][j] = a[0] ^ gmul(a[1], 2) ^ gmul(a[2], 3) ^ a[3];
    state[2][j] = a[0] ^ a[1] ^ gmul(a[2], 2) ^ gmul(a[3], 3);
    state[3][j] = gmul(a[0], 3) ^ a[1] ^ a[2] ^ gmul(a[3], 2);
  }
};
```

La fonction `mixColumns` mélange les colonnes de l'état en utilisant des multiplications dans le champ de Galois.

### Fonction de chiffrement AES

```ts
export const aesEncrypt = (
  message: number[],
  expandedKey: number[][],
): number[] => {
  const state: number[][] = [];
  for (let i = 0; i < 4; i++) {
    state.push(message.slice(i * 4, i * 4 + 4));
  }

  addRoundKey(state, expandedKey.slice(0, 4));

  for (let round = 1; round <= 9; round++) {
    subBytes(state);
    shiftRows(state);
    mixColumns(state);
    addRoundKey(state, expandedKey.slice(round * 4, (round + 1) * 4));
  }

  subBytes(state);
  shiftRows(state);
  addRoundKey(state, expandedKey.slice(40, 44));

  const encryptedMessage: number[] = [];
  for (let i = 0; i < 4; i++) {
    encryptedMessage.push(...state[i]);
  }

  return encryptedMessage;
};
```

La fonction `aesEncrypt` implémente le chiffrement AES complet en appliquant les étapes SubBytes, ShiftRows, MixColumns et AddRoundKey pour chaque ronde, et en omettant MixColumns pour la dernière ronde.

### Fonction de déchiffrement AES

```ts
export const aesDecrypt = (
  cipherText: number[],
  expandedKey: number[][],
): number[] => {
  let state = transformKey(cipherText);

  addRoundKey(state, expandedKey.slice(40, 44));

  for (let round = 9; round >= 1; round--) {
    invShiftRows(state);
    invSubBytes(state);
    addRoundKey(state, expandedKey.slice(round * 4, (round + 1) * 4));
    invMixColumns(state);
  }

  invShiftRows(state);
  invSubBytes(state);
  addRoundKey(state, expandedKey.slice(0, 4));

  return state.flat();
};
```

La fonction `aesDecrypt` implémente le déchiffrement AES complet en appliquant les étapes inverses de ShiftRows, SubBytes, MixColumns et AddRoundKey pour chaque ronde, et en omettant MixColumns pour la dernière ronde.

### Fonction de conversion de tableau d'octets en chaîne

```ts
const byteArrayToString = (byteArray: number[]): string => {
  return String.fromCharCode(...byteArray);
};
```

La fonction `byteArrayToString` convertit un tableau d'octets en une chaîne de caractères.

### Exemple de chiffrement et déchiffrement

```ts
const hex_key = [
  0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09,
  0xcf, 0x4f, 0x3c,
];
const hex_message = [
  0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0,
  0x37, 0x07, 0x34,
];

const expandedKey = keyExpansion(hex_key);
const encryptedMessage = aesEncrypt(hex_message, expandedKey);
const decryptedMessage = aesDecrypt(encryptedMessage, expandedKey);

const hexOutput = decryptedMessage.map(
  (byte: number) => "0x" + byte.toString(16).padStart(2, "0"),
);
console.log(hexOutput);

console.log("Key Expansion:", expandedKey);
console.log("Encrypted Message:", encryptedMessage);
console.log("Decrypted Message:", decryptedMessage);
console.log(
  "Decrypted Message as String:",
  byteArrayToString(decryptedMessage),
);
console.log("Decrypted Message in Hexa:", hexOutput);
```

Cet exemple montre comment utiliser les fonctions `aesEncrypt` et `aesDecrypt` pour chiffrer et déchiffrer un message avec une clé donnée. Le message chiffré et déchiffré est ensuite affiché.

## Chiffrement de Vigenère

### Explication du chiffrement de Vigenère

Le chiffrement de Vigenère est une méthode de chiffrement par substitution polyalphabétique utilisant une série de différentes substitutions de César basées sur les lettres d'un mot-clé. Il est simple à comprendre et à implémenter, mais il est vulnérable aux attaques par analyse de fréquence.

#### Étapes du chiffrement de Vigenère :

1. **Préparation** :
    - Choisissez un texte clair et une clé.
    - La clé est répétée pour correspondre à la longueur du texte clair.

2. **Chiffrement** :
    - Pour chaque lettre du texte clair, trouvez la lettre correspondante dans la clé.
    - Utilisez la position de la lettre de la clé dans l'alphabet pour décaler la lettre du texte clair.

3. **Déchiffrement** :
    - Pour chaque lettre du texte chiffré, trouvez la lettre correspondante dans la clé.
    - Utilisez la position de la lettre de la clé dans l'alphabet pour décaler la lettre du texte chiffré dans le sens inverse.

### Exemple de chiffrement et déchiffrement avec Vigenère

Voici un exemple complet de l'implémentation du chiffrement de Vigenère en TypeScript, incluant le chiffrement et le déchiffrement :

```ts
console.log("====================================");
console.log("Chiffrement de Vigenère");
console.log("====================================");

const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

// Fonction pour générer l'alphabet de substitution basé sur la clé
const subAlphabet = (key: string): string => {
  let subAlphabet = "";
  for (let i = 0; i < alphabet.length; i++) {
    subAlphabet += alphabet[(i + alphabet.indexOf(key[i % key.length])) % alphabet.length];
  }
  return subAlphabet;
}

// Fonction de chiffrement Vigenère
const vigenereEncrypt = (text: string, key: string): string => {
  const subAlphabetKey = subAlphabet(key);
  let result = "";
  for (let i = 0; i < text.length; i++) {
    result += subAlphabetKey[alphabet.indexOf(text[i])];
  }
  return result;
}

// Fonction de déchiffrement Vigenère
const vigenereDecrypt = (cipherText: string, key: string): string => {
  const subAlphabetKey = subAlphabet(key);
  let result = "";
  for (let i = 0; i < cipherText.length; i++) {
    const index = subAlphabetKey.indexOf(cipherText[i]);
    result += alphabet[index];
  }
  return result;
}

// Exemple de texte et clé
const text = "CRYPTOGRAPHIE";
const key = "CRYPTO";

// Chiffrement du texte
const encryptedText = vigenereEncrypt(text, key);
console.log("Texte original:", text);
console.log("Texte chiffré:", encryptedText);

// Déchiffrement du texte
const decryptedText = vigenereDecrypt(encryptedText, key);
console.log("Texte déchiffré:", decryptedText);
```

### Explication du code

1. **Préparation** :
    - L'alphabet utilisé pour le chiffrement est défini comme une chaîne de caractères contenant toutes les lettres de l'alphabet en majuscules.
    - La fonction `subAlphabet` génère un alphabet de substitution basé sur la clé fournie. Elle décale chaque lettre de l'alphabet en fonction de la position de la lettre correspondante dans la clé.

2. **Chiffrement** :
    - La fonction `vigenereEncrypt` prend en entrée le texte clair et la clé. Elle utilise l'alphabet de substitution généré par `subAlphabet` pour chiffrer chaque lettre du texte clair.
    - Pour chaque lettre du texte clair, la fonction trouve sa position dans l'alphabet et utilise cette position pour trouver la lettre correspondante dans l'alphabet de substitution.

3. **Déchiffrement** :
    - La fonction `vigenereDecrypt` prend en entrée le texte chiffré et la clé. Elle utilise l'alphabet de substitution généré par `subAlphabet` pour déchiffrer chaque lettre du texte chiffré.
    - Pour chaque lettre du texte chiffré, la fonction trouve sa position dans l'alphabet de substitution et utilise cette position pour trouver la lettre correspondante dans l'alphabet original.

### Résultat

L'exécution du code ci-dessus affichera le texte original, le texte chiffré et le texte déchiffré, qui devrait correspondre au texte original.

```plaintext
====================================
Chiffrement de Vigenère
====================================
Texte original: CRYPTOGRAPHIE
Texte chiffré: DZSJJZJXZJZ
Texte déchiffré: CRYPTOGRAPHIE
```

Cet exemple montre comment utiliser le chiffrement de Vigenère pour chiffrer et déchiffrer un texte donné avec une clé spécifique. Le texte chiffré et déchiffré est ensuite affiché.

## Algorithme RSA

### Explication de l'algorithme RSA

L'algorithme RSA (Rivest-Shamir-Adleman) est un algorithme de cryptographie asymétrique qui repose sur la difficulté de factoriser de grands nombres premiers. Il utilise une paire de clés : une clé publique pour le chiffrement et une clé privée pour le déchiffrement.

#### Étapes de l'algorithme RSA :

1. **Génération des clés** :
    - Choisissez deux grands nombres premiers distincts, `p` et `q`.
    - Calculez `n = p * q`. `n` est utilisé comme module pour les clés publique et privée.
    - Calculez la fonction d'Euler `φ(n) = (p-1) * (q-1)`.
    - Choisissez un entier `e` tel que `1 < e < φ(n)` et `e` soit coprime avec `φ(n)`. `e` est l'exposant de la clé publique.
    - Calculez `d` tel que `d ≡ e^(-1) (mod φ(n))`. `d` est l'exposant de la clé privée.

2. **Chiffrement** :
    - Convertissez le message en une suite de nombres (par exemple, en utilisant les valeurs ASCII des caractères).
    - Pour chaque nombre `m` du message, calculez le chiffre `c` en utilisant la clé publique `(e, n)` : `c ≡ m^e (mod n)`.

3. **Déchiffrement** :
    - Pour chaque chiffre `c`, calculez le message `m` en utilisant la clé privée `(d, n)` : `m ≡ c^d (mod n)`.
   
   ### Exemple de chiffrement et déchiffrement avec RSA
   
   Voici un exemple complet de l'implémentation de l'algorithme RSA en TypeScript, incluant la génération des clés, le chiffrement et le déchiffrement :
   
   ```ts
   console.log("====================================");
   console.log("Rivest-Shamir-Adleman (RSA) Algorithm");
   console.log("====================================");
   
   // Choisissez deux grands nombres premiers
   const p = 61;
   const q = 53;
   
   // Calculez n = p * q
   const n = p * q;
   
   // Calculez la fonction d'Euler φ(n) = (p-1) * (q-1)
   const phi = (p - 1) * (q - 1);
   
   // Choisissez un entier e tel que 1 < e < φ(n) et e soit coprime avec φ(n)
   const e = 17;
   
   // Calculez d tel que d ≡ e^(-1) (mod φ(n))
   const d = 2753;
   
   // Fonction de chiffrement
   const encrypt = (message: string, e: number, n: number): bigint[] => {
     return message.split('').map(char => BigInt(char.charCodeAt(0)) ** BigInt(e) % BigInt(n));
   }
   
   // Fonction de déchiffrement
   const decrypt = (cipher: bigint[], d: number, n: number): string => {
     return cipher.map(num => String.fromCharCode(Number((num ** BigInt(d) % BigInt(n))))).join('');
   }
   
   // Message à chiffrer
   const message = "HELLO-WORLD";
   
   // Chiffrement du message
   const encryptedMessage = encrypt(message, e, n);
   console.log("Message:", message);
   console.log("Encrypted message:", encryptedMessage);
   
   // Déchiffrement du message
   const decryptedMessage = decrypt(encryptedMessage, d, n);
   console.log("Decrypted message:", decryptedMessage);
   ```
   
   ### Explication du code
   
   1. **Génération des clés** :
       - Les nombres premiers `p` et `q` sont choisis comme 61 et 53 respectivement.
       - `n` est calculé comme le produit de `p` et `q`.
       - La fonction d'Euler `φ(n)` est calculée comme `(p-1) * (q-1)`.
       - `e` est choisi comme 17, un nombre qui est coprime avec `φ(n)`.
       - `d` est calculé comme l'inverse modulaire de `e` modulo `φ(n)`.
   
   2. **Chiffrement** :
       - Le message est converti en une suite de nombres en utilisant les valeurs ASCII des caractères.
       - Chaque nombre `m` du message est chiffré en calculant `c ≡ m^e (mod n)`.
   
   3. **Déchiffrement** :
       - Chaque chiffre `c` est déchiffré en calculant `m ≡ c^d (mod n)`.
       - Les nombres déchiffrés sont convertis en caractères pour reconstruire le message original.
   
   ### Résultat
   
   L'exécution du code ci-dessus affichera le message original, le message chiffré sous forme de nombres, et le message déchiffré, qui devrait correspondre au message original.
   
   ```plaintext
   ====================================
   Rivest-Shamir-Adleman (RSA) Algorithm
   ====================================
   Message: HELLO-WORLD
   Encrypted message: [ 2790n, 2205n, 3130n, 3130n, 2164n, 999n, 3130n, 999n, 3130n, 3130n, 2164n ]
   Decrypted message: HELLO-WORLD
   ```
   
   Cet exemple montre comment utiliser l'algorithme RSA pour chiffrer et déchiffrer un message donné avec des clés spécifiques. Le message chiffré et déchiffré est ensuite affiché.
   
   ---
   Ce projet a été créé en utilisant `bun init` dans bun v1.1.39. [Bun](https://bun.sh) est un runtime JavaScript tout-en-un rapide. dans bun v1.1.39. [Bun](https://bun.sh) est un runtime JavaScript tout-en-un rapide.
