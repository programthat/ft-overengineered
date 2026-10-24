// View the original at:
// https://github.com/daily3014/rbx-cryptography
// With the version being used:
// https://github.com/daily3014/rbx-cryptography/tree/6147c4702726ab59c4b31ed9304dbe8bb843f05f
// This port only contains stuff from /src

// You can view the license at
// https://github.com/daily3014/rbx-cryptography/blob/6147c4702726ab59c4b31ed9304dbe8bb843f05f/LICENSE

// roblox-ts interface ported by @ek587290135 (github @programthat)

// Make sure you research each function before using! Some are not very secure!
// (The luau implementation has more details for each)

// ===============================

// This is repeated a couple of times in the script
type EntropyProvider = (BytesLeft: number) => buffer | undefined;
interface CSPRNG {
	BlockExpansion: boolean;

	SizeTarget: number;
	RekeyAfter: number;

	Key: buffer;
	Nonce: buffer;
	Buffer: buffer;

	Counter: number;
	BufferPosition: number;
	BufferSize: number;
	BytesLeft: number;

	EntropyProviders: Array<EntropyProvider>;

	Reseed: (CustomEntropy?: buffer) => void;
	AddEntropyProvider: (ProviderFunction: EntropyProvider) => void;
	RemoveEntropyProvider: (ProviderFunction: EntropyProvider) => void;

	Random: () => number;
	RandomInt: (Min: number, Max?: number) => number;
	RandomNumber: (Min: number, Max?: number) => number;
	RandomBytes: (Count: number) => buffer;
	RandomString: (Length: number, AsBuffer?: boolean) => string | buffer;
	RandomHex: (Length: number) => string;
	Ed25519ClampedBytes: (Input: buffer) => buffer;
	Ed25519Random: () => buffer;
}

// ===============================

interface KMAC {
	KMAC128: (Data: buffer, Key: buffer, Output: buffer, CustomBuffer?: buffer) => LuaTuple<[string, buffer]>;
	KMAC256: (Data: buffer, Key: buffer, Output: buffer, CustomBuffer?: buffer) => LuaTuple<[string, buffer]>;
}

interface SHA2 {
	SHA224: (Message: buffer) => LuaTuple<[string, buffer]>;
	SHA256: (Message: buffer) => LuaTuple<[string, buffer]>;
	SHA384: (Message: buffer) => LuaTuple<[string, buffer]>;
	SHA512: (Message: buffer) => LuaTuple<[string, buffer]>;
}

interface SHA3 {
	SHA3_224: (Message: buffer) => LuaTuple<[string, buffer]>;
	SHA3_256: (Message: buffer) => LuaTuple<[string, buffer]>;
	SHA3_384: (Message: buffer) => LuaTuple<[string, buffer]>;
	SHA3_512: (Message: buffer) => LuaTuple<[string, buffer]>;
	SHAKE128: (Message: buffer, OutputBytes: number) => LuaTuple<[string, buffer]>;
	SHAKE256: (Message: buffer, OutputBytes: number) => LuaTuple<[string, buffer]>;
}

// idk who Blake is or why there are 3 of them
interface Blake3 {
	Digest: (Message: buffer, Length?: number) => LuaTuple<[string, buffer]>;
	BigestKeyed: (Message: buffer, Key: buffer, Length?: number) => LuaTuple<[string, buffer]>;
	DeriveKey: (Context: buffer) => (Material: buffer, Length?: number) => LuaTuple<[string, buffer]>;
}

type HashFunction = (...args: unknown[]) => LuaTuple<[string, buffer]>;
interface Hashing {
	HMAC: (
		message: buffer,
		key: buffer,
		hashFunction: HashFunction,
		blockSizeBytes: number,
		bigEndian?: boolean,
	) => LuaTuple<[string, buffer]>;
	HKDF: (
		IKM: buffer,
		Salt: buffer | undefined,
		Info: buffer | undefined,
		Length: number,
		HashFunction: HashFunction,
		BlockSize: number,
		HashLength: number,
		BigEndian?: boolean,
	) => buffer;
	KMAC: KMAC;
	MD5: (Message: buffer, Salt?: buffer) => LuaTuple<[string, buffer]>;
	SHA1: (Message: buffer, Salt: buffer) => string;
	SHA2: SHA2;
	SHA3: SHA3;
	XXH32: (Message: buffer, Seed?: number) => number;
	Blake2b: (InputData: buffer, OutputLength?: number, KeyData?: buffer) => LuaTuple<[string, buffer]>;
	Blake3: Blake3;
	MurMur: (Message: buffer, Seed?: number) => number;
}

// ===============================

interface Checksums {
	CRC32: (Message: buffer, Mode?: "Jam" | "Iso", Hex?: boolean) => number | string;
	Adler: (Message: buffer) => number;
}

// ===============================

interface Conversions {
	ToHex: (Buffer: buffer) => string;
	FromHex: (Hex: string | buffer) => buffer;
}

interface Base64 {
	Encode: (Input: buffer) => buffer;
	Decode: (Input: buffer) => buffer;
}

interface Utilities {
	RandomString: (Length: number, AsBuffer?: boolean) => string | buffer;
	Conversions: Conversions;
	Base64: Base64;
	CSPRNG: CSPRNG;
}

// ===============================

interface AEAD {
	ChaCha20: (Data: buffer, Key: buffer, Nonce: buffer, Counter?: number, Rounds?: number) => buffer;
	XChaCha20: (Data: buffer, Key: buffer, Nonce: buffer, Counter?: number, Rounds?: number) => buffer;
	// Poly wants 1305 crackers
	Poly1305: (Message: buffer, Key: buffer) => buffer;

	Encrypt: (
		Message: buffer,
		key: buffer,
		Nonce: buffer,
		AdditionalAuthData?: buffer,
		Rounds?: number,
		UseXChaCha20?: boolean,
	) => LuaTuple<[buffer, buffer]>;
	Decrypt: (
		Ciphertext: buffer,
		Key: buffer,
		Nonce: buffer,
		Tag: buffer,
		AdditionalAuthData?: buffer,
		Rounds?: number,
		UseXChaCha20?: boolean,
	) => buffer | undefined;
}

interface AES {
	Encrypt: (Plaintext: buffer, Key: buffer, IV: buffer, AAD?: buffer) => LuaTuple<[buffer, buffer]>;
	Decrypt: (Ciphertext: buffer, Key: buffer, IV: buffer, Tag: buffer, AAD?: buffer) => LuaTuple<[boolean, buffer?]>;
}

interface Simon {
	Encrypt: (PlaintextBuffer: buffer, KeyBuffer: buffer) => buffer;
	Decrypt: (CipherBuffer: buffer, KeyBuffer: buffer) => buffer;
}

interface Speck {
	Encrypt: (PlaintextBuffer: buffer, KeyBuffer: buffer) => buffer;
	Decrypt: (CipherBuffer: buffer, KeyBuffer: buffer) => buffer;
}

interface Encryption {
	AEAD: AEAD;
	AES: AES;
	XOR: (StringBuffer: buffer, KeyBuffer: buffer) => buffer;
	Simon: Simon;
	Speck: Speck;
}

// ===============================

interface X25519 {
	Mask: (SecretKey: buffer) => buffer;
	MaskSignature: (SignatureSecretKey: buffer) => buffer;
	Remask: (MaskedKey: buffer) => buffer;
	MaskComponent: (MaskedKey: buffer) => buffer;
	PublicKey: (MaskedKey: buffer) => buffer;
	Exchange: (MaskedSecretKey: buffer, TheirPublicKey: buffer) => LuaTuple<[buffer, buffer]>;
}

type SignatureEntry = {
	PublicKey: buffer;
	Message: buffer;
	Signature: buffer;
};
interface EdDSA {
	CSPRNG: CSPRNG;
	X25519: X25519;

	PublicKey: (SecretKey: buffer) => buffer;
	Sign: (Message: buffer, SecretKey: buffer, PublicKey: buffer) => buffer;
	Verify: (Message: buffer, PublicKey: buffer, Signature: buffer) => boolean;
	VerifyBatch: (Entries: SignatureEntry) => boolean;
}

interface ML_DSA_N {
	D: number;
	Tau: number;
	Gamma1: number;
	Gamma2: number;
	K: number;
	L: number;
	Eta: number;
	Beta: number;
	Omega: number;
	Lambda: number;

	KeygenSeedByteLen: number;
	PubKeyByteLen: number;
	SecKeyByteLen: number;
	SigningSeedByteLen: number;
	SigByteLen: number;

	KeyGen: (Seed: buffer, PubKey: buffer, SecKey: buffer) => void;
	Sign: (Msg: buffer, Rnd: buffer, SecKey: buffer, Ctx: buffer, Sig: buffer) => boolean;
	SignInternal: (MPrime: buffer, Rnd: buffer, SecKey: buffer, Sig: buffer) => boolean;
	SignMu: (Mu: buffer, Rnd: buffer, SecKey: buffer, Sig: buffer) => boolean;
	Verify: (Msg: buffer, PubKey: buffer, Ctx: buffer, Sig: buffer) => boolean;
	GenerateKeys: () => LuaTuple<[buffer, buffer]>;
}

interface MlDSA {
	CSPRNG: CSPRNG;

	// The types are the same but some of the internal values change
	ML_DSA_44: ML_DSA_N;
	ML_DSA_65: ML_DSA_N;
	ML_DSA_87: ML_DSA_N;

	PubKeyLen: (K: number, D: number) => number;
	SecKeyLen: (K: number, L: number, Eta: number, D: number) => number;
	SigLen: (K: number, L: number, Gamma1: number, Omega: number, Lambda: number) => number;
}

interface MLKEM_N {
	KeyGen: (D: buffer, Z: buffer) => LuaTuple<[buffer, buffer]>;
	Encapsulate: (Message: buffer, PublicKey: buffer) => LuaTuple<[buffer?, buffer?]>;
	Decapsulate: (Ciphertext: buffer, SecretKey: buffer) => buffer;
	GenerateKeys: () => LuaTuple<[buffer, buffer]>;
	ValidateDecapsulationKey: (SecretKey: buffer) => boolean;
}

interface MlKEM {
	CSPRNG: CSPRNG;

	KeyGen: (K: number, Eta1: number, D: buffer, Z: buffer) => LuaTuple<[buffer, buffer]>;
	Encapsulate: (
		Message: buffer,
		K: number,
		Eta1: number,
		Eta2: number,
		Du: number,
		Dv: number,
		PublicKey: buffer,
	) => LuaTuple<[buffer?, buffer?]>;
	Decapsulate: (
		Ciphertext: buffer,
		K: number,
		Eta1: number,
		Eta2: number,
		Du: number,
		Dv: number,
		SecretKey: buffer,
	) => buffer;
	SecretsEqual: (Secret1: buffer, Secret2: buffer) => boolean;
	ValidateDecapsulationKey: (K: number, SecretKey: buffer) => boolean;

	// The types are the same but some of the internal values change
	MLKEM_512: MLKEM_N;
	MLKEM_768: MLKEM_N;
	MLKEM_1024: MLKEM_N;
}

interface Verification {
	EdDSA: EdDSA;
	MlDSA: MlDSA;
	MlKEM: MlKEM;
}

// ===============================

interface CryptographyModule {
	Hashing: Hashing;
	Checksums: Checksums;
	Utilities: Utilities;
	Encryption: Encryption;
	Verification: Verification;
}
declare const Cryptography: CryptographyModule;
export = Cryptography;
