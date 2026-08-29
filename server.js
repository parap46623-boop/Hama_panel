import express from "express";
import Database from "better-sqlite3";
const app=express(), db=new Database("licenses.db"), PORT=process.env.PORT||3000;
const ADMIN_TOKEN=process.env.ADMIN_TOKEN||"change-me";
app.use(express.json()); app.use(express.static("public"));
const auth=(req,res,next)=>req.get("Authorization")===`Bearer ${ADMIN_TOKEN}`?next():res.status(401).json({error:"Unauthorized"});
db.exec(`CREATE TABLE IF NOT EXISTS licenses(id INTEGER PRIMARY KEY,key TEXT UNIQUE,type TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'active',expires_at TEXT,device_id TEXT,created_at TEXT NOT NULL)`);
function key(){const a="ABCDEFGHJKLMNPQRSTUVWXYZ23456789";return [...Array(6)].map(()=>a[Math.floor(Math.random()*a.length)]).join("")}
app.post("/api/admin/keys",auth,(req,res)=>{let days=+req.body.days||30,type=String(req.body.type||"normal");if(!["normal","vip"].includes(type))return res.status(400).json({error:"Invalid type"});let k;do{k=key()}while(db.prepare("select 1 from licenses where key=?").get(k));let e=new Date(Date.now()+days*864e5).toISOString();db.prepare("insert into licenses(key,type,expires_at,created_at) values(?,?,?,?)").run(k,type,e,new Date().toISOString());res.json({success:true,key:k,type,expires_at:e})});
app.get("/api/admin/keys",auth,(req,res)=>res.json(db.prepare("select * from licenses order by id desc").all()));
app.post("/api/admin/revoke",auth,(req,res)=>res.json({success:!!db.prepare("update licenses set status='revoked' where key=?').run(String(req.body.key||"").toUpperCase()).changes}));
app.post("/api/authorize",(req,res)=>{let k=String(req.body.key||"").trim().toUpperCase(),d=String(req.body.device_id||""),r=db.prepare("select * from licenses where key=?").get(k);if(!r)return res.json({success:false,status:"invalid"});if(r.status!=="active")return res.json({success:false,status:r.status});if(Date.parse(r.expires_at)<=Date.now())return res.json({success:false,status:"expired"});if(r.device_id&&r.device_id!==d)return res.json({success:false,status:"device_mismatch"});if(!r.device_id&&d)db.prepare("update licenses set device_id=? where key=?").run(d,k);res.json({success:true,status:"active",license_type:r.type,expires_at:r.expires_at,features:{vip:r.type==="vip"}})});
app.listen(PORT,()=>console.log(`Panel on :${PORT}`));