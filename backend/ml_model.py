"""Random Forest training, prediction and model evaluation on a bundled demo dataset."""
from pathlib import Path
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, classification_report
from features import url_features, email_features

LABELS = ["legitimate", "suspicious", "phishing"]
FEATURE_COLUMNS = ["length", "host_length", "dot_count", "subdomain_count", "hyphen_count", "digit_count", "special_char_count", "at_symbol", "ip_domain", "https", "shortener", "suspicious_keyword_count", "query_length", "has_punycode", "path_length", "url_count", "urgent_count", "credential_count", "attachment_count", "risky_attachment", "uppercase_ratio", "exclamation_count", "sender_valid"]


def demo_dataset():
    """Small deterministic educational dataset. Replace with vetted labeled data for real evaluation."""
    rows=[]
    url_examples = [
      ("https://www.wikipedia.org", "legitimate"), ("https://www.python.org/downloads/", "legitimate"), ("https://www.microsoft.com/en-us/", "legitimate"), ("https://docs.google.com/document", "legitimate"), ("https://github.com/openai", "legitimate"), ("https://www.nhs.uk/conditions/", "legitimate"),
      ("http://news-example.net/article?id=42", "suspicious"), ("https://login-support-example.com/help", "suspicious"), ("https://bit.ly/4abcXYZ", "suspicious"), ("https://offers-example.org/account-update", "suspicious"), ("http://example.net/redirect?next=home", "suspicious"), ("https://secure-info-example.com/portal", "suspicious"),
      ("http://192.168.1.22/verify/login", "phishing"), ("http://paypa1-account-verify.example/login?password=1", "phishing"), ("http://xn--paypa-4ve.example/secure", "phishing"), ("http://account-suspended-verify.example/otp", "phishing"), ("http://10.0.0.5/confirm-account", "phishing"), ("http://signin-password-reset.example/urgent", "phishing")]
    for url,label in url_examples:
        f=url_features(url); f.update(kind="url", label=label); rows.append(f)
    email_examples = [
      ("help@wikipedia.org","Your requested article","Here is the article link you asked for. https://www.wikipedia.org/","",[],"legitimate"),
      ("team@python.org","Documentation update","The latest documentation is available at https://docs.python.org/.","",[],"legitimate"),
      ("newsletter@museum.example","Monthly newsletter","Thank you for subscribing. Read our monthly update on our website.","",[],"legitimate"),
      ("support@shop-example.net","Order status","Your order has shipped. Track it from your account dashboard.","",[],"legitimate"),
      ("service@account-help-example.com","Account notice","Please review the general notice in your account when convenient.","",[],"suspicious"),
      ("updates@billing-example.net","Payment receipt","A payment receipt is available. If you did not make this purchase, contact support.","",[],"suspicious"),
      ("support1234@secure-account-example.com","Security update","Please sign in to review recent account activity.","",[],"suspicious"),
      ("alert@short.example","Link shared","Please review this shortened link: https://bit.ly/example","",[],"suspicious"),
      ("security@paypa1-account-verify.example","URGENT: account suspended","Verify your password and OTP immediately within 24 hours or your account will be closed! http://192.0.2.4/login?redirect=account","",["account_update.exe"],"phishing"),
      ("admin@verify-login-example.com","FINAL WARNING!!!","Click here immediately to verify your identity. Send your password, OTP and security code now! http://account-login.example/verify","",[],"phishing"),
      ("billing@payment-verify-example.net","Payment failed urgently","Your wallet is locked. Login and confirm your credentials now: http://10.0.0.8/secure","",["invoice.js"],"phishing"),
      ("help@account-secure-verify.example","Action required","Within 24 hours your account will be suspended. Verify your password and one time password immediately!","",[],"phishing")]
    for sender,subject,body,html,attachments,label in email_examples:
        f=email_features(sender,subject,body,html,attachments); f.update(kind="email",label=label); rows.append(f)
    # Deterministic variation adds modest training volume without changing class patterns.
    base=list(rows)
    for i in range(3):
        for item in base:
            copy=item.copy()
            for key in ("length","special_char_count","digit_count","path_length"):
                if key in copy: copy[key]=max(0,int(copy[key]) + (i+1)*((len(str(copy.get("label"))) % 3)+1))
            rows.append(copy)
    return pd.DataFrame(rows).fillna(0)


def train_models():
    df=demo_dataset()
    models={}
    for kind in ("url","email"):
        part=df[df.kind==kind].copy()
        X=part[FEATURE_COLUMNS].fillna(0)
        y=part.label
        model=RandomForestClassifier(n_estimators=180, max_depth=8, min_samples_leaf=1, class_weight="balanced", random_state=42)
        model.fit(X,y)
        models[kind]=model
    return models

MODELS=train_models()


def predict(kind, features):
    model=MODELS[kind]
    row={c:features.get(c,0) for c in FEATURE_COLUMNS}
    frame=pd.DataFrame([row], columns=FEATURE_COLUMNS).fillna(0)
    probabilities=model.predict_proba(frame)[0]
    probs={str(label):float(prob) for label,prob in zip(model.classes_,probabilities)}
    return max(probs,key=probs.get), probs


def evaluate_models():
    """Holdout metrics on synthetic educational examples; metrics are not real-world guarantees."""
    df=demo_dataset()
    results={}
    for kind in ("url","email"):
        part=df[df.kind==kind]
        X=part[FEATURE_COLUMNS].fillna(0); y=part.label
        X_train,X_test,y_train,y_test=train_test_split(X,y,test_size=.3,random_state=42,stratify=y)
        model=RandomForestClassifier(n_estimators=180,max_depth=8,class_weight="balanced",random_state=42)
        model.fit(X_train,y_train); pred=model.predict(X_test)
        results[kind]={
          "accuracy":round(float(accuracy_score(y_test,pred)),4),
          "precision_macro":round(float(precision_score(y_test,pred,average="macro",zero_division=0)),4),
          "recall_macro":round(float(recall_score(y_test,pred,average="macro",zero_division=0)),4),
          "f1_macro":round(float(f1_score(y_test,pred,average="macro",zero_division=0)),4),
          "labels":LABELS,
          "confusion_matrix":confusion_matrix(y_test,pred,labels=LABELS).tolist(),
          "report":classification_report(y_test,pred,labels=LABELS,output_dict=True,zero_division=0),
          "dataset_size":int(len(part)),
          "test_size":int(len(y_test)),
          "note":"Synthetic demo dataset only. Evaluate with a larger, independently collected and labeled dataset before operational use."
        }
    return results
