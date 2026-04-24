import express from 'express';
import path from 'node:path';

import {db} from "./db/index.js"
import { usersTable } from "./db/schema.js";
import { eq } from 'drizzle-orm';

import crypto from 'crypto'

import JWT from 'jsonwebtoken'
import type { JWTClaims } from './utils/user-token.js';
import {PRIVATE_KEY, PUBLIC_KEY} from "./utils/cert.js"

import * as jose from 'jose'
import { importSPKI, exportJWK } from "jose";
 

const app = express()
const PORT = process.env.PORT || 3000

app.use(express.json())
app.use(express.static(path.resolve("public")));


app.get("/", (req,res) => {
    res.send("Hello from oidc server ")
})

app.get("/health", async (req, res) => {
  try {
    await db.execute("SELECT 1");
    res.json({ status: "ok", db: "connected" });
  } catch {
    res.status(500).json({ status: "error", db: "down" });
  }
});


app.get("/.well-known/openid-configuration", async(req, res) => {
  const ISSUER = `http://localhost:${PORT}`
  return res.json({
    issuer: ISSUER,
    authorization_endpoint: `${ISSUER}/o/authenticate`,
    userinfo_endpoint: `${ISSUER}/o/userinfo`,
    jwks_uri: `${ISSUER}/.well-known/jwks.json`
  })
}) 

app.get("/.well-known/jwks.json", async (_, res) => {
  const key = await importSPKI(PUBLIC_KEY, "RS256");
  const jwk = await exportJWK(key);

  return res.json({
    keys: [jwk],
  });
});

app.get("/o/authenticate", async (req, res) => {
  res.sendFile(path.resolve("public", "authenticate.html"))
})

app.post("/o/authenticate/sign-up", async(req, res) => {

  try{ 
    
    const {firstName, lastName,  email, password } = req.body

  if(!firstName || !lastName || !email || !password){
    return res.status(400).json({
      message: "All the fields are required!"
    })
  }
 
  const userEmailResult = await db.select()
  .from(usersTable)
  .where(eq(usersTable.email, email))

  if(userEmailResult.length > 0){
    return res.status(400).json({
      error: "duplicate entry",
      message: `user with ${email} already exists`
    })
  }
 
  const salt  = crypto.randomBytes(32).toString('hex')
  const hashedPassword = crypto.createHash("sha256").update(password + salt ).digest('hex')

  await db.insert(usersTable).values({
    firstName,
    lastName: lastName ?? null,
    email,
    password:hashedPassword,
    salt,
  })

  return res.json({
    status: "ok",
    message: "user created successfully"
  })

}catch (err: any) {
    console.log("FULL ERROR 👉", err);
    console.log("CAUSE 👉", err.cause); // 👈 yahi asli error hota hai

    return res.status(500).json({
      error: err.message,
      cause: err.cause?.message
    });
  }

})

app.post("/o/authenticate/sign-in", async(req, res) => {
  try{

    const{email, password} = req.body

    if(!email || !password){
      return res.status(400).json({
        message: "both fiels are required"
      })
    }

    const [userSelect] = await db
    .select()
    .from(usersTable)
    .where(eq(usersTable.email, email))

    if(!userSelect) {
      return res.status(404).json({
        message: `user with this ${email} does not exist`
      })
    }

    const salt = userSelect.salt!

    const hash = crypto
    .createHash("sha256")
    .update(password + salt)
    .digest('hex')

    if(hash !== userSelect.password){
      return res.status(403).json({
        message: "email or password is not valid "
      })
    }

    const ISSUER = `http://localhost:3000/${PORT}`
    const now = Math.floor(Date.now()/1000)


    const claims: JWTClaims = {
      iss: ISSUER,
      sub: userSelect.id,
      email: userSelect.email,
      email_verified: String(userSelect.emailVerified),
      exp: now + 3600,
      family_name: userSelect.lastName ?? "",
      given_name: userSelect.firstName ?? "",
      name: [userSelect.firstName ?? "", userSelect.lastName ?? ""].filter(Boolean).join(" "),
      picture: userSelect.profileImageURL ?? ""

    }

    const token = JWT.sign(claims, PRIVATE_KEY, { algorithm : "RS256"} )


    return res.status(200).json({
      success: true,
      message: "Login successfull done",
      token : token

    })






  }catch(err: any){
    console.log("error", err)
    console.log("Error message", err.message)
    console.log("Error cause", err.cause)

  }

})  

app.get("/o/userinfo", async(req, res) => {

  const header = req.headers.authorization 

  if(!header || !header.startsWith("Bearer ")){
    return res.status(400).json({
      message : "token invalid"
    })
  }

    const token = header.split(" ")[1]

    let claims: JWTClaims;
  try {
    claims = JWT.verify(token ?? "", PUBLIC_KEY, {
      algorithms: ["RS256"],
    }) as unknown as JWTClaims;
  } catch {
    res.status(401).json({ message: "Invalid or expired token." });
    return;
  }

  const [userSelect] = await db
  .select().from(usersTable)
  .where(eq(usersTable.id, claims.sub))

  if(!userSelect){
    return res.status(404).json({
      message: "User not found"
    })
  }

  return res.status(200).json({
    sub: userSelect.id,
    email: userSelect.email,
    email_verified: userSelect.emailVerified,
    given_name: userSelect.firstName,
    family_name: userSelect.lastName,
    name: [userSelect.firstName, userSelect.lastName].filter(Boolean).join(" "),
    picture: userSelect.profileImageURL,

  })




})

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`)
})

// ========================================== Learning =======================================================
/*
1.jose ek library hai jo cryptographic keys (PEM) ko JWT/OIDC-compatible formats (JWK/JWKS) me convert karke signing,
 verification aur key sharing ko standard way me handle karti hai.

2.yaha dekh tere JWT claims kya hai string hai isliye change krna pada  

3. mene jose ka new version add  kiyah usme JWK.askey() wala synrax nahi nahi alg syntax tha but usme PUBLIC_KEY ko 
as a string nhi padha jata hai as a buffer liya jata to fir muhe cert.ts mein jaake change karna oada tha as "utf8".

4. 👉 jose (v6) ko PEM key string format me hi chahiye
problem ye nahi tha ki usse string nahi chahiye… , but jo mai return kar raha tha vo buffer tha 

5. ❌ JWK.asKey() → removed
✅ importSPKI() → new way

👉 but input type (string PEM) same hi raha


================================================== String vs Buffer ===============================================
const buf = readFileSync("file.txt");
console.log(buf);
result:  <Buffer 48 65 6c 6c 6f>

const str = readFileSync("file.txt", "utf8");
console.log(str);
result: Hello

 */