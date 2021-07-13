from flask import Flask, render_template, request
from detector import gogo
import json
from malwareanalysis import malwarescanner
from werkzeug.utils import secure_filename
import os
from trainer import starttraining

app = Flask(__name__)
app.debug = True
app.config['UPLOAD_FOLDER'] = './uploads'
app.config['RULES_FOLDER'] = './rules'
app.secret_key = 'devkey'

@app.route('/')
def hello():
    return render_template('home.html')

@app.route('/logscan')
def detector():
    return render_template('logscan.html')

@app.route('/uploadrule')
def uploadrule():
    return render_template('yaraupload.html')

@app.route('/malwarescan')
def malware():
    return render_template('malwarescan.html')

@app.route('/trainlog')
def trainlog():
    data = json.loads(starttraining())
    return render_template('trainlog.html', data=data)

@app.route('/availablerules')
def availablerules():
    rulelist = []
    for _ in os.listdir("rules"):
        rulelist.append(_)
    return render_template('yararules.html', rulelist=rulelist)

@app.route('/loghandler', methods = ['POST'])
def loghandler():
   if request.method == 'POST':
      f = request.files['file']
      filename = secure_filename(f.filename)
      f.save(os.path.join(app.config['UPLOAD_FOLDER'],filename))
      data = json.loads(gogo(os.path.join(app.config['UPLOAD_FOLDER'],filename)))
      os.remove(os.path.join(app.config['UPLOAD_FOLDER'],filename))
      return render_template('logresult.html', data=data, filename=filename)

@app.route('/malwarehandler', methods = ['POST'])
def malwarehandler():
   if request.method == 'POST':
      f = request.files['file']
      filename = secure_filename(f.filename)
      f.save(os.path.join(app.config['UPLOAD_FOLDER'],filename))
      data = json.loads(malwarescanner(os.path.join(app.config['UPLOAD_FOLDER'],filename)))
      os.remove(os.path.join(app.config['UPLOAD_FOLDER'],filename))
      return render_template('malwareresult.html', data=data, filename=filename)

@app.route('/yarahandler', methods = ['POST'])
def yarahandler():
   if request.method == 'POST':
      f = request.files['file']
      filename = secure_filename(f.filename)
      f.save(os.path.join(app.config['RULES_FOLDER'],filename))
      rulelist = []
      for _ in os.listdir("rules"):
          rulelist.append(_)
      return render_template('yararules.html', filename=filename, rulelist=rulelist)

if __name__ == '__main__':
    app.run()