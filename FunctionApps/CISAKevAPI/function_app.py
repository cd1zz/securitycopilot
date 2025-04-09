import azure.functions as func
import logging
import json
import requests

app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

@app.route(route="kev")
def kev_api(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("KEV API HTTP trigger function processed a request.")
    
    try:
        response = requests.get(CISA_KEV_URL, timeout=10)
        response.raise_for_status()
        kev_data = response.json()
        vulns = kev_data.get("vulnerabilities", [])

        # Query params
        cve = req.params.get("cveID")
        vendor = req.params.get("vendor")
        product = req.params.get("product")
        keyword = req.params.get("q")

        # Filtering
        if cve:
            vulns = [v for v in vulns if v["cveID"].lower() == cve.lower()]
        if vendor:
            vulns = [v for v in vulns if vendor.lower() in v["vendorProject"].lower()]
        if product:
            vulns = [v for v in vulns if product.lower() in v["product"].lower()]
        if keyword:
            vulns = [v for v in vulns if keyword.lower() in json.dumps(v).lower()]

        return func.HttpResponse(json.dumps(vulns), mimetype="application/json")

    except Exception as e:
        logging.exception("Error processing KEV request")
        return func.HttpResponse(json.dumps({"error": str(e)}), status_code=500, mimetype="application/json")
