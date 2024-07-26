from vuln.models import vulnerabilities
import requests


#Funcion para consumir api nva
def consumir_api():
    try:
        info_api = requests.get('https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=Cloud')
        data = info_api.json()
        vulnerabilities = data['vulnerabilities']
        return vulnerabilities
    except:
        print("error in consumir_api")


#Funcion para modelar datos según necesidad
def modelar_data_api(data):
    vulnerability_results = []
    try:
        for dat in data:
            cve_id = dat['cve']['id']
            sourceIdentifier = dat['cve']['sourceIdentifier']
            published = dat['cve']['published']
            lastModified = dat['cve']['lastModified']
            descriptions =  dat['cve']['descriptions']
            datos = {'id': cve_id, 'sourceIdentifier' : sourceIdentifier, 'published':  published, 'lastModified': lastModified, 'descriptions': descriptions}
            vulnerability_results.append(datos)
        return vulnerability_results
    except:
        print('error in modelar_data_api')
        

#Funcion para excluir vulnerabildiades fixeadas
def excluir_fix(data):
    vulnerability_nofix = []
    vulnerabilities_fix = []
    queryset = vulnerabilities.objects.all()
    
    for vul in queryset:
        vulnerabilities_fix.append(vul.vul_id)
    
    try:
        for dat in data:
            if dat['cve']['id'] not in vulnerabilities_fix:
                cve_id = dat['cve']['id']
                sourceIdentifier = dat['cve']['sourceIdentifier']
                published = dat['cve']['published']
                lastModified = dat['cve']['lastModified']
                descriptions =  dat['cve']['descriptions']
                datos = {'id': cve_id, 'sourceIdentifier' : sourceIdentifier, 'published':  published, 'lastModified': lastModified, 'descriptions': descriptions}
                vulnerability_nofix.append(datos)
        return vulnerability_nofix
    except:
        print('error in excluir_fix')
        
        
def filter_vulnerability_severity(severity):
    try:
        info_api = requests.get(f'https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=Cloud&cvssV2Severity={severity}')
        data = info_api.json()
        vulnerabilities = data['vulnerabilities']
        return vulnerabilities
    except:
        print("error in filter_vulnerability_severity")
