from fastapi import FastAPI, HTTPException, Query
from pymongo import MongoClient
import requests
from bson import ObjectId
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="CVE API")

# -------------------------
# Enable CORS for frontend
# -------------------------
origins = ["http://localhost:5173"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------------
# MongoDB setup
# -------------------------
client = MongoClient("mongodb://localhost:27017/")
db = client["nvd_db"]
cve_collection = db["cves"]

# -------------------------
# Helper: Convert Mongo documents to JSON
# -------------------------
def serialize_doc(doc):
    doc["_id"] = str(doc["_id"])
    return doc

# -------------------------
# Home endpoint
# -------------------------
@app.get("/")
def home():
    return {"message": "CVE API is running!"}

# -------------------------
# Fetch CVEs from NVD API
# -------------------------
@app.get("/cves/fetch")
def fetch_cves(results_per_page: int = 50):
    NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"resultsPerPage": results_per_page}

    response = requests.get(NVD_API_URL, params=params)
    if response.status_code != 200:
        raise HTTPException(status_code=500, detail=f"NVD API failed: {response.status_code}")

    data = response.json()
    cves = data.get("vulnerabilities", [])
    if not cves:
        raise HTTPException(status_code=404, detail="No CVEs returned by NVD API")

    inserted_ids = []
    for item in cves:
        cve = item.get("cve")
        if not cve:
            continue
        cve_id = cve.get("id")
        if not cve_id:
            continue
        # Upsert using _id = cve_id
        cve_collection.replace_one({"_id": cve_id}, cve, upsert=True)
        inserted_ids.append(cve_id)

    return {
        "message": "CVEs fetched and stored successfully",
        "total_fetched": len(cves),
        "inserted_ids": inserted_ids
    }

# -------------------------
# List CVEs with pagination & severity filtering
# -------------------------
@app.get("/cves/list")
def list_cves(
    page: int = Query(1, ge=1),
    limit: int = Query(10, ge=1),
    severity: str = None
):
    query = {}
    if severity:
        # Filter using cvssMetricV2 array
        query["metrics.cvssMetricV2"] = {"$elemMatch": {"baseSeverity": severity.upper()}}

    total = cve_collection.count_documents(query)
    skips = (page - 1) * limit
    cursor = cve_collection.find(query).skip(skips).limit(limit)

    data = [serialize_doc(doc) for doc in cursor]

    return {
        "total": total,
        "page": page,
        "limit": limit,
        "data": data
    }
