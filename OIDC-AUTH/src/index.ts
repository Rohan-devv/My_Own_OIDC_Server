import express from 'express';
import path from 'node:path';

import {db} from "./db/index.js"
import { usersTable } from "./db/schema.js";
import { eq } from 'drizzle-orm';

import crypto from 'crypto'
 

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

    return res.status(200).json({
      success: true,
      message: "Login successfull done"

    })






  }catch(err: any){
    console.log("error", err)
    console.log("Error message", err.message)
    console.log("Error cause", err.cause)

  }

})

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`)
})