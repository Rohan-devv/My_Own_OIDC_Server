import express from 'express';
import path from 'node:path';

import {db} from "./db/index.js"
import { usersTable } from "./db/schema.js";
 

const app = express()
const port = process.env.PORT || 3000

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

app.post("/users", async (req, res) => {
  try{
    const {name,age, email} = req.body

    if(!name || !age || !email){
        return res.status(400).json({
            message: "all fields are  required!"
        })
    }

    const result = await db
    .insert(usersTable)
    .values({name, age, email})
    .returning()

    return res.status(201).json({
        success: "true",
        message: "User created successfully",
        data: result
    })

  }catch (err: any) {
  console.error("FULL ERROR 👉", err);

  if (err.code === "23505") {
    return res.status(409).json({ error: "Email already exists" });
  }

  res.status(500).json({ error: "Internal Server Error" });
}
});


app.listen(port, () => {
    console.log(`Server is running on port ${port}`)
})