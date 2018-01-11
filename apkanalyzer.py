#!/usr/bin/env python
# -*- coding: utf-8 -*-

from flask import Flask, render_template, request, redirect
import os
import hashlib
import sys
import json
import sqlite3
from redis import Redis
from rq import Queue
from werkzeug import secure_filename

app = Flask(__name__)
reload(sys)
sys.setdefaultencoding('utf8')

# Remove on production
#app.debug = True

# QR-Worker Redis connection
q = Queue(connection=Redis())

# Project folders setup
PROJECT_ROOT = '~/apkanalyzer/'
UPLOADS_FOLDER = PROJECT_ROOT+'uploads/'
ANALYSIS_FOLDER = PROJECT_ROOT+'analysis/'
REPORTS_FOLDER = PROJECT_ROOT+'reports/'
SQLITE_DB = PROJECT_ROOT+'db/apkanalyzer.db'
DROIDBOX  = '/opt/DroidBox/scripts/droidbox.py'
ALLOWED_EXTENSIONS = set(['apk'])

# Filetypes allowed in upload (by extension)
def allowed_file(filename):
	return '.' in filename and filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS

def dynamicAnalysis(file_path=None, outDir=None):
	# Start DroidBox and wait for process end
	p = subprocess.Popen(['python', DROIDBOX, file_path, '60', outDir], stderr=subprocess.STDOUT)
	ret_code = p.wait()
	return ret_code
	
def staticAnalysis(file_path=None, outDir=None):
	# Load APK to be analysed
	a = apk.APK(file_path)
	b = AndroguardS(file_path)
	d = dvm.DalvikVMFormat(a.get_dex())
	x = analysis.uVMAnalysis(b.get_vm())
	classes = b.get_vm().get_classes_names()
	vm = b.get_vm()

	# Create a dict with static analysis info
	output = dict()
	output['package_name'] = a.get_package()
	output['app_name'] = a.get_app_name()
	output['version_code'] = a.get_androidversion_code()
	output['version_name'] = a.get_androidversion_name()
	output['permissions'] = a.get_details_permissions()
	output['target_sdk_version'] = a.get_target_sdk_version()
	output['max_sdk_version'] = a.get_max_sdk_version()
	output['min_sdk_version'] = a.get_min_sdk_version()
	output['main_activity'] = a.get_main_activity()
	#output['activities'] = a.get_activities()
	output['services'] = a.get_services()
	output['receivers'] = a.get_receivers()
	output['providers'] = a.get_providers()
	output['date'] = time.strftime('%d/%m/%Y')
	output['time'] = time.strftime('%H:%M:%S')
	output['cert'] = a.get_signature_name()
	
	output['activities'] = dict()
	for activity in a.get_activities():
		output['activities'][activity] = a.get_intent_filters('activity', activity)
	# Get permissions usages and add to dict
	perms_access = x.get_tainted_packages().get_permissions([])
	output['permissions_usage'] = dict()
	i = 0
	for perm in perms_access:
		i = i+1
		output['permissions_usage'][i] = dict()
		output['permissions_usage'][i]['permission'] = perm
		output['permissions_usage'][i]['path'] = analysis.get_Paths(b, perms_access[perm])
	# Get APK risks and add to dict
	r = risk.RiskIndicator()
	r.add_risk_analysis(risk.RedFlags())
	r.add_risk_analysis(risk.FuzzyRisk())
	output['risk'] = r.with_apk_direct(a, d, x)

	hash = hashlib.md5()
	with(open(file_path)) as f:
		for chunk in iter(lambda: f.read(4096), b""):
			hash.update(chunk)
	MD5 = hash.hexdigest()
	
	# Save to sqlite
	conn = sqlite3.connect(SQLITE_DB)
	c = conn.cursor()
	c.execute('INSERT INTO reports VALUES (?, ?, ?, ?)', (MD5, a.get_package(), a.get_app_name(), output['risk']['FuzzyRisk']['VALUE']))
	conn.commit()
	conn.close()
	
	# Write dict with static analysis data to a json file
	with open(outDir+'static.json','w+') as jsonfile:
		jsonfile.write(json.dumps(output, sort_keys=True, indent=4))
	return 'Static analysis done'

@app.route('/')
@app.route('/index.html')
def index():
	return render_template('index.html')

@app.route('/analyse', methods=['GET', 'POST'])
def analyse():
	if request.method == 'POST':
		file = request.files['file']
		if file and allowed_file(file.filename):
			file.save(UPLOADS_FOLDER+secure_filename(file.filename))
			# MD5 of the uploaded file
			hash = hashlib.md5()
			with(open(UPLOADS_FOLDER+secure_filename(file.filename))) as f:
				for chunk in iter(lambda: f.read(4096), b""):
					hash.update(chunk)
			apk_hash = hash.hexdigest()
			os.rename(UPLOADS_FOLDER+secure_filename(file.filename), UPLOADS_FOLDER+apk_hash+'.apk')
			file_path = UPLOADS_FOLDER+apk_hash+'.apk'
			#file.save(UPLOADS_FOLDER+file.filename)

			# Analysis out directory
			outDir = ANALYSIS_FOLDER + apk_hash + '/'
			if os.path.isfile(REPORTS_FOLDER+apk_hash+'.html'):
				return redirect('/report/'+apk_hash)
			else:
				if not os.path.exists(outDir):
					os.makedirs(outDir)
				q.enqueue_call(func=staticAnalysis, args=(file_path, outDir), timeout=300)
				q.enqueue_call(func=dynamicAnalysis, args=(file_path, outDir), timeout=600)
				return redirect('/report/'+apk_hash)
		else:
			return 'Invalid file'
	else:
		return 'Nothing to do here'


@app.route('/report/<report_md5>')
def show_report(report_md5=None):
	# If a report is already generated, load it
	if os.path.isfile(REPORTS_FOLDER+report_md5+'.html'):
		return open(REPORTS_FOLDER+report_md5+'.html', 'r').read()
	else:
		# If dynamic analysis not ended, show "Analyzing APK" page
		if not os.path.isfile(ANALYSIS_FOLDER+report_md5+'/dynamic.json'):
			return render_template('analyzing.html')
		else:
			try:
				import GeoIP
				geoIP = GeoIP.new(GeoIP.GEOIP_MEMORY_CACHE)
				# Generate the analysis report
				static = json.load(open(ANALYSIS_FOLDER+report_md5+'/static.json'))
				dynamic = json.load(open(ANALYSIS_FOLDER+report_md5+'/dynamic.json'))
				html = render_template('result.html', static=static, dynamic=dynamic, geoIP=geoIP)
				report_url = REPORTS_FOLDER+report_md5+'.html'
				f_html = open(report_url, 'w')
				f_html.write(html)
				f_html.close()
				return html
			except:
				return 'Analysis report generation failed'

@app.route('/reports')
def recent():
	conn = sqlite3.connect(SQLITE_DB)
	c = conn.cursor()
	reports = c.execute('SELECT * FROM reports')
	'''
	# Get files in reports folder. Eash file should be an html report
	dir = os.listdir(REPORTS_FOLDER)
	files = []
	for file in dir:
		files.append(file.replace('.html', ''))
	'''
	return render_template('reports.html', reports=reports)
	
@app.route('/search', methods=['GET', 'POST'])
def search():
	if request.method == 'GET':
		return render_template('search.html')
	if request.method == 'POST':
		import sqlite3
		conn = sqlite3.connect(SQLITE_DB)
		c = conn.cursor()
		result = c.execute("SELECT * FROM reports WHERE MD5 LIKE '%' || ? || '%' OR package_name LIKE '%' || ? || '%' OR app_name LIKE '%' || ? || '%'", (request.form.get('search'), request.form.get('search'), request.form.get('search')))
		return render_template('search_result.html', result=result)
if __name__ == '__main__':
	app.run(host='0.0.0.0', port=8080)
