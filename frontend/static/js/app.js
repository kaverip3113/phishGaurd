const $ = (id) => document.getElementById(id);
let currentType = 'url';
const tabs = [...document.querySelectorAll('.tab')];
tabs.forEach(tab => tab.addEventListener('click', () => {
  currentType = tab.dataset.type;
  tabs.forEach(t => t.classList.toggle('active', t === tab));
  $('urlFields').classList.toggle('hidden', currentType !== 'url');
  $('emailFields').classList.toggle('hidden', currentType !== 'email');
  $('errorBox').classList.add('hidden');
}));
$('sampleBtn').addEventListener('click', () => {
  if (currentType === 'url') $('url').value = 'http://192.0.2.4/verify-account?redirect=login';
  else {
    $('sender').value = 'security@paypa1-account-verify.example';
    $('subject').value = 'URGENT: Your account will be suspended';
    $('body').value = 'Verify your password and OTP immediately within 24 hours or your account will be closed! Click here: http://192.0.2.4/login?redirect=account';
    $('emailHtml').value = '<a href="http://192.0.2.4/login">https://www.paypal.com/login</a>';
    $('attachments').value = 'account_update.exe';
  }
});
$('clearBtn').addEventListener('click', () => {
  ['url','sender','subject','body','emailHtml','attachments'].forEach(id => $(id).value='');
  $('results').classList.add('hidden'); $('errorBox').classList.add('hidden');
});
$('analysisForm').addEventListener('submit', async e => {
  e.preventDefault(); $('errorBox').classList.add('hidden'); $('loading').classList.remove('hidden'); $('analyzeBtn').disabled=true;
  const payload = currentType === 'url' ? {type:'url',url:$('url').value} : {type:'email',sender:$('sender').value,subject:$('subject').value,body:$('body').value,email_html:$('emailHtml').value,attachments:$('attachments').value};
  try {
    const response=await fetch('/api/analyze',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
    const data=await response.json(); if(!response.ok) throw new Error(data.error || 'Analysis failed.');
    renderResult(data);
  } catch(err) { $('errorBox').textContent=err.message; $('errorBox').classList.remove('hidden'); }
  finally {$('loading').classList.add('hidden'); $('analyzeBtn').disabled=false;}
});
function renderResult(data) {
  $('results').classList.remove('hidden'); $('classification').textContent=data.classification; $('modelPrediction').textContent=data.model_prediction;
  $('score').textContent=data.risk_score; $('ruleScore').textContent=`${data.rule_score}/100`; $('summary').textContent=data.summary;
  $('urlCount').textContent=data.urls.length; $('featureCount').textContent=Object.keys(data.features).length;
  $('meterFill').style.width=`${data.risk_score}%`; $('scoreRing').style.borderColor=color(data.classification); $('scoreRing').style.background=softColor(data.classification); $('meterFill').style.background=color(data.classification);
  $('resultBadge').textContent=data.classification.toUpperCase(); $('resultBadge').style.color=color(data.classification); $('resultBadge').style.background=softColor(data.classification);
  $('probabilities').innerHTML=''; Object.entries(data.probabilities).sort((a,b)=>b[1]-a[1]).forEach(([label,value])=>{
    const row=document.createElement('div'); row.className='prob-row';
    const name=document.createElement('span'); name.textContent=label;
    const track=document.createElement('div'); track.className='prob-track'; const fill=document.createElement('div'); fill.className='prob-fill'; fill.style.width=`${value}%`; fill.style.background=color(label); track.append(fill);
    const pct=document.createElement('strong'); pct.textContent=`${value.toFixed(1)}%`; row.append(name,track,pct); $('probabilities').append(row);
  });
  $('indicators').innerHTML=''; data.indicators.forEach(text=>{const li=document.createElement('li');li.textContent=text;$('indicators').append(li);});
  $('urlDetails').innerHTML=''; data.urls.forEach(item=>{const div=document.createElement('div');div.className='url-result';const strong=document.createElement('strong');strong.textContent=item.url;div.append(strong);const p=document.createElement('p');p.textContent=`Rule score: ${item.rule_score}/100`;div.append(p);item.reasons.forEach(r=>{const q=document.createElement('p');q.textContent='• '+r;div.append(q)});$('urlDetails').append(div)});
  $('results').scrollIntoView({behavior:'smooth',block:'start'});
}
function color(label){return label==='phishing'?'#c0394f':label==='suspicious'?'#b7791f':'#16865b'}
function softColor(label){return label==='phishing'?'#fff0f2':label==='suspicious'?'#fff8e8':'#eefbf5'}
$('loadMetrics').addEventListener('click', async()=>{
  const button=$('loadMetrics');button.disabled=true;button.textContent='Calculating…';
  try {const r=await fetch('/api/evaluation');if(!r.ok)throw new Error('Could not load evaluation metrics.');const data=await r.json();$('metricsContent').innerHTML='';
    Object.entries(data).forEach(([kind,m])=>{
      const title=document.createElement('h4');title.className='matrix-caption';title.textContent=`${kind.toUpperCase()} classifier`; $('metricsContent').append(title);
      const summary=document.createElement('div');summary.className='metric-summary';[['Accuracy',m.accuracy],['Precision (macro)',m.precision_macro],['Recall (macro)',m.recall_macro],['F1-score (macro)',m.f1_macro]].forEach(([name,val])=>{const card=document.createElement('div');card.className='eval-stat';const s=document.createElement('span');s.textContent=name;const b=document.createElement('strong');b.textContent=(val*100).toFixed(1)+'%';card.append(s,b);summary.append(card)});$('metricsContent').append(summary);
      const caption=document.createElement('p');caption.className='matrix-caption';caption.textContent=`Confusion matrix — rows: actual, columns: predicted (test samples: ${m.test_size})`; $('metricsContent').append(caption);
      const wrap=document.createElement('div');wrap.className='matrix-wrap';const table=document.createElement('table');table.className='matrix';const labels=m.labels;const thead=document.createElement('thead');const tr=document.createElement('tr');const corner=document.createElement('th');corner.textContent='Actual ↓ / Predicted →';tr.append(corner);labels.forEach(l=>{const th=document.createElement('th');th.textContent=l;tr.append(th)});thead.append(tr);table.append(thead);const tbody=document.createElement('tbody');m.confusion_matrix.forEach((row,i)=>{const tr=document.createElement('tr');const th=document.createElement('th');th.textContent=labels[i];tr.append(th);row.forEach((v,j)=>{const td=document.createElement('td');td.textContent=v;if(i===j)td.className='diagonal';tr.append(td)});tbody.append(tr)});table.append(tbody);wrap.append(table);$('metricsContent').append(wrap);
    });
  } catch(e){$('metricsContent').textContent=e.message;} finally{button.disabled=false;button.textContent='Refresh metrics';}
});
