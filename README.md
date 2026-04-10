# 🛡️ Shamir Secret Sharing Toolkit

A pair of client-side tools for splitting secrets into shares using [Shamir’s Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing) over GF(2⁸). No servers, no tracking, no data leaves your browser.

![React](https://img.shields.io/badge/React-18+-61dafb?logo=react&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-blue)
![Offline](https://img.shields.io/badge/Works-Offline-green)

-----

## What’s Inside

### 1. Shamir Secret Sharing Tool

A general-purpose encoding/decoding tool for any text secret.

- **Split** any text into *n* shares with a configurable threshold *k*
- **Combine** *k* or more shares to reconstruct the original
- Supports up to 255 shares (GF(256) field limit)
- Hex-encoded shares with one-click copy

### 2. Seed Phrase Vault

A purpose-built tool for protecting BIP-39 cryptocurrency wallet seed phrases.

- **BIP-39 validation** — checks word count (12/15/18/21/24) and format
- **Offline-first** — live network status banner warns if you’re online
- **Masked input** — seed phrase hidden by default with show/hide toggle
- **Guided wizard** — step-by-step flow: enter → configure → generate
- **Download shares** — export all shares as a `.txt` file
- **Viewport toggle** — switch between mobile and desktop layouts to preview responsiveness
- Uses `crypto.getRandomValues()` for cryptographically secure randomness

-----

## How It Works

Shamir’s Secret Sharing splits a secret into *n* pieces such that any *k* pieces can reconstruct it, but *k − 1* or fewer reveal absolutely nothing about the original.

The scheme works by:

1. Treating each byte of the secret as a constant term of a random polynomial of degree *k − 1*
1. Evaluating that polynomial at *n* distinct points over the finite field GF(256)
1. Each evaluation point becomes a share
1. Reconstruction uses Lagrange interpolation at *x = 0* to recover the constant term

All arithmetic is performed in GF(2⁸) using the irreducible polynomial *x⁸ + x⁴ + x³ + x + 1* (`0x11b`), which ensures every non-zero element has a multiplicative inverse.

-----

## Getting Started

### Prerequisites

- Node.js 18+
- npm or yarn

### Installation

```bash
git clone https://github.com/your-username/shamir-secret-sharing.git
cd shamir-secret-sharing
npm install
```

### Running Locally

```bash
npm run dev
```

Open <http://localhost:5173> in your browser.

### Building for Production

```bash
npm run build
```

The output in `dist/` is a fully static site — serve it from anywhere or open `index.html` directly.

-----

## Project Structure

```
├── src/
│   ├── shamir-secret-sharing.jsx   # General-purpose SSS tool
│   └── seed-phrase-vault.jsx       # BIP-39 seed phrase tool
├── package.json
└── README.md
```

Both files are self-contained React components with zero external dependencies beyond React itself. Each component includes:

- GF(256) finite field arithmetic (log/exp tables, multiply, divide)
- Polynomial evaluation and Lagrange interpolation
- Hex encoding/decoding for share serialization
- Complete UI with responsive layout

-----

## Security Considerations

### What this tool does well

- **Zero network transmission** — all computation happens in the browser
- **Cryptographically secure randomness** — the Seed Phrase Vault uses `crypto.getRandomValues()` for polynomial coefficients
- **Information-theoretic security** — fewer than *k* shares reveal zero information about the secret (this is a mathematical guarantee, not an implementation detail)

### What to be aware of

- **The general tool uses `Math.random()`** — the Shamir Secret Sharing tool uses `Math.random()` for coefficient generation, which is not cryptographically secure. For sensitive secrets, use the Seed Phrase Vault or swap in `crypto.getRandomValues()`
- **No checksum or integrity verification** — if you combine the wrong shares or too few shares, you’ll get garbage output rather than an error (the Seed Phrase Vault mitigates this with BIP-39 format validation)
- **Browser environment** — while nothing is transmitted, your browser’s memory, extensions, clipboard history, and OS-level keyloggers are outside the scope of this tool. For high-value secrets, use an air-gapped machine
- **Share storage is your responsibility** — the security of the scheme depends entirely on how you distribute and store the shares

### Recommended Practices

1. **Go offline** before entering sensitive secrets
1. **Verify recovery** before destroying your original secret
1. **Store shares separately** — the whole point is that no single location holds enough to reconstruct
1. **Use the Seed Phrase Vault** (not the general tool) for cryptocurrency seed phrases
1. **Close the tab** when you’re done — don’t leave secrets in browser memory

-----

## Share Format

Each share is a hex string structured as:

```
[xx][yy yy yy yy ...]
 │    └── polynomial evaluation bytes (one per secret byte)
 └────── evaluation point (1-indexed, 01-ff)
```

For example, a share starting with `03` was evaluated at point *x = 3*. The remaining bytes are the GF(256) evaluations for each byte of the original secret.

-----

## Technical Details

|Property     |Value                                                         |
|-------------|--------------------------------------------------------------|
|Finite field |GF(2⁸) with irreducible polynomial `0x11b`                    |
|Max shares   |255 (field element limit)                                     |
|Min threshold|2                                                             |
|Encoding     |UTF-8 → byte array → per-byte polynomial sharing              |
|Share format |Hex string: `[1 byte x-coord][n bytes data]`                  |
|Randomness   |`crypto.getRandomValues()` (Vault) / `Math.random()` (General)|

-----

## Contributing

Contributions are welcome. Some ideas:

- [ ] Embed the full BIP-39 wordlist for per-word validation
- [ ] Add share checksums / HMAC for integrity verification
- [ ] QR code generation for share distribution
- [ ] Support for binary file splitting
- [ ] SLIP-39 compatibility
- [ ] Threshold signature scheme integration

Please open an issue before submitting large changes.

-----

## License

MIT — see <LICENSE> for details.

-----

## Acknowledgments

- [Adi Shamir](https://en.wikipedia.org/wiki/Adi_Shamir) — for the original 1979 paper *“How to Share a Secret”*
- The finite field arithmetic uses precomputed log/exp tables for GF(2⁸), a standard technique from AES implementations
