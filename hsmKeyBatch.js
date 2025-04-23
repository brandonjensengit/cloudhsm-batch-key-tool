require('dotenv').config();
 const axios = require('axios');
 const ethers = require('ethers');
 
 // Configuration moved to .env
 const API_URL = "https://sbx-rest-api.cloudshsm.com/v1/key";
 const AUTH_TOKEN = process.env.SECUROSYS_TOKEN_VALUE;
 const NUM_KEYS = parseInt(process.env.NUM_KEYS, 10); // Number of key pairs
 const KEY_PREFIX = process.env.KEY_PREFIX; // Prefix for key names

 // Check configuration and limits
 const MAX_KEYS = 100;
 if (!NUM_KEYS || !KEY_PREFIX) {
  console.error("Error: NUM_KEYS or KEY_PREFIX not found in .env file.");
  process.exit(1);
 } else if (NUM_KEYS > MAX_KEYS) {
  console.error(`Error: NUM_KEYS (${NUM_KEYS}) exceeds the maximum allowed (${MAX_KEYS}).`);
  process.exit(1);
 }
 
 // Retry Mechanism
 const MAX_RETRIES = 3;
 const RETRY_DELAY = 1000; // 1 second (in milliseconds)
 
 async function makeApiRequest(url, data, headers, method = 'post') {
  let attempt = 0;
  while (attempt < MAX_RETRIES) {
   try {
    let response;
    if (method.toLowerCase() === 'post') {
     response = await axios.post(url, data, { headers });
    } else if (method.toLowerCase() === 'get') {
     response = await axios.get(url, { headers });
    } else {
     throw new Error(`Unsupported HTTP method: ${method}`);
    }
 
    if (response.status !== 429) { // If not rate limited, return response
     return response;
    }
 
    attempt++;
    console.warn(`Rate limit hit. Retrying in ${RETRY_DELAY / 1000} seconds... (Attempt ${attempt}/${MAX_RETRIES})`);
    await new Promise(resolve => setTimeout(resolve, RETRY_DELAY)); // Wait before retrying
 
   } catch (error) {
    attempt++;
    console.error(`API request failed (Attempt ${attempt}/${MAX_RETRIES}):`, error);
    if (attempt === MAX_RETRIES) {
     throw error; // If max retries reached, re-throw the last error
    }
    await new Promise(resolve => setTimeout(resolve, RETRY_DELAY));
   }
  }
  throw new Error(`Max retries (${MAX_RETRIES}) exceeded for API request.`); // If loop exits without returning
 }
 
 // Create Keys Function
 async function createKeyPair(label) {
  try {
  const response = await makeApiRequest(
   API_URL,
   {
    label: label,
    algorithm: "EC",
    curveOid: "1.3.132.0.10",
    attributes: {
     encrypt: false,
     decrypt: false,
     verify: true,
     sign: true,
     wrap: false,
     unwrap: false,
     derive: false,
     bip32: false,
     extractable: false,
     modifiable: false,
     destroyable: false,
     sensitive: true,
     copyable: false
    }
   },
   {
    "Authorization": `Bearer ${AUTH_TOKEN}`,
    "Content-Type": "application/json"
   }
  );
 
  if (response.status === 201) {
   return true;
  } else {
   console.error(`Failed to create key pair "${label}". Status: ${response.status}, Data:`, response.data);
   return false;
  }
  } catch (error) {
  console.error(`Error creating key pair "${label}":`, error);
  return false;
  }
 }
 
 // Fetch and convert Address
 async function fetchPublicAddress(keyLabel) {
  try {
  const messages = ["00", "01"]; // Two different messages
  let recoveredAddress = null;
 
  for (const message of messages) {
   const signRequest = {
    signRequest: {
     payload: Buffer.from(message).toString("base64"),
     payloadType: "UNSPECIFIED",
     signKeyName: keyLabel,
     signatureType: "ETH",
     signatureAlgorithm: "KECCAK256_WITH_ECDSA"
    }
   };
 
   const response = await makeApiRequest(
    "https://sbx-rest-api.cloudshsm.com/v1/synchronousSign",
    signRequest,
    {
     "Authorization": `Bearer ${AUTH_TOKEN}`,
     "Content-Type": "application/json"
    }
   );
 
   if (response.status === 200) {
    const sig = Buffer.from(response.data.signature, "base64").toString("ascii");
    const messageHash = ethers.keccak256(ethers.toUtf8Bytes(message));
    const currentAddress = ethers.recoverAddress(messageHash, "0x" + sig).toLowerCase(); // Normalize to lowercase
 
    if (recoveredAddress === null) {
     recoveredAddress = currentAddress; // Store the first recovered address
    } else if (recoveredAddress !== currentAddress) {
     // If addresses don't match, it's a potential issue
     console.error(`Address mismatch for key ${keyLabel} with message "${message}": Expected ${recoveredAddress}, Got ${currentAddress}`);
     return null; // Or throw an error, depending on your error handling strategy
    }
   } else {
    console.error(`Failed to fetch public address for key "${keyLabel}" with message "${message}". Status: ${response.status}, Data:`, response.data);
    return null;
   }
  }
 
  return recoveredAddress; // Return the consistent recovered address
  } catch (error) {
  console.error(`Error fetching public address for key "${keyLabel}":`, error);
  return null;
  }
 }
 
 async function main() {
  // create a list of prefixed incrementing key labels to generate
  const keyLabels = Array.from(
   { length: NUM_KEYS },
   (_, idx) => `${KEY_PREFIX}_${idx}`,
  );
  // concurrently generate each key in `keyLabels`, fetch its public address, and print the results
  const generatedKeys = await Promise.all(keyLabels.map(async (keyLabel) => {
   const created = await createKeyPair(keyLabel)
   if (created) {
    console.log(`Key ${keyLabel} has been created. Fetching its public address...`)
    const publicAddress = await fetchPublicAddress(keyLabel);
    if (publicAddress) {
     return { keyLabel, publicAddress }
    }
   }
  }));
  console.log('\n') // print a new line to the console
  for (const key of generatedKeys.filter(k => k)) {
   console.log(`HSM Key Name: ${key.keyLabel}, Address: ${key.publicAddress.toLowerCase()}`)
  }
 }
 
 main().catch(error => {
  console.error("Script failed:", error);
 });
 