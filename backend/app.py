from pathlib import Path
import sys
from flask import Flask, jsonify, request, render_template
from features import extract_urls, url_features, email_features, rule_analysis
from ml_model import predict, evaluate_models

BASE_DIR=Path(__file__).resolve().parent
FRONTEND_DIR=BASE_DIR.parent / "frontend"
app=Flask(__name__, template_folder=str(FRONTEND_DIR / "templates"), static_folder=str(FRONTEND_DIR / "static"), static_url_path="/static")

@app.get("/")
def index():
    return render_template("index.html")

@app.get("/api/health")
def health():
    return jsonify({"status":"ok","model":"RandomForestClassifier","classes":["legitimate","suspicious","phishing"]})

@app.get("/api/evaluation")
def evaluation():
    return jsonify(evaluate_models())

@app.post("/api/analyze")
def analyze():
    data=request.get_json(silent=True) or {}
    kind=data.get("type","url")
    if kind not in ("url","email"):
        return jsonify({"error":"type must be 'url' or 'email'."}),400
    if kind=="url":
        url=(data.get("url") or "").strip()
        if not url: return jsonify({"error":"Enter a URL to analyze."}),400
        features=url_features(url)
        rule_score,reasons=rule_analysis("url",url,features)
        urls=[url]
        details=[{"url":url,"rule_score":rule_score,"reasons":reasons}]
    else:
        sender=(data.get("sender") or "").strip(); subject=(data.get("subject") or "").strip(); body=(data.get("body") or "").strip(); html=(data.get("email_html") or "").strip()
        raw_attachments=data.get("attachments",[])
        attachments=[x.strip() for x in raw_attachments.split(",") if x.strip()] if isinstance(raw_attachments,str) else raw_attachments
        if not any([sender,subject,body,html]): return jsonify({"error":"Enter at least one email field."}),400
        text=f"{sender} {subject} {body} {html}"
        features=email_features(sender,subject,body,html,attachments)
        rule_score,reasons=rule_analysis("email",text,features,attachments)
        urls=extract_urls(text)
        details=[]
        for u in urls:
            uf=url_features(u); us,ur=rule_analysis("url",u,uf); details.append({"url":u,"rule_score":us,"reasons":ur})
    label,probabilities=predict(kind,features)
    # Blend ML probability and transparent rule score into a bounded risk score.
    ml_risk=100*(probabilities.get("phishing",0)+0.45*probabilities.get("suspicious",0))
    score=round(max(0,min(100,0.65*ml_risk+0.35*rule_score)))
    if score>=65 or label=="phishing": final_label="phishing"
    elif score>=30 or label=="suspicious": final_label="suspicious"
    else: final_label="legitimate"
    if not reasons: reasons=["No major rule-based warning indicators were detected; still verify the destination and sender."]
    return jsonify({"type":kind,"classification":final_label,"model_prediction":label,"risk_score":score,"rule_score":rule_score,"probabilities":{k:round(v*100,2) for k,v in probabilities.items()},"features":features,"indicators":reasons,"urls":details,"summary":f"The {kind} was classified as {final_label.upper()} with a risk score of {score}/100. This is an automated estimate, not a guarantee."})

if __name__=="__main__":
    app.run(host="127.0.0.1",port=5000,debug=True)
