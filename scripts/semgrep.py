import requests
import sys
import os
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# Configurações do DefectDojo
url = 'https://demo.defectdojo.org'

def get_engagement_id_from_name(dojo_token, url, product_name, engagement_name):
    # Busca o ID do produto pelo nome
    product_endpoint = f"{url}/api/v2/products/"
    product_response = requests.get(
        product_endpoint,
        params={"name": product_name},
        headers={"Authorization": f"Token {dojo_token}"},
        verify=False
    )
    products = product_response.json()
    
    if product_response.status_code != 200 or products['count'] == 0:
        sys.exit(f'Produto não encontrado ou falha ao recuperar: {product_response.text}')
    
    product_id = products['results'][0]['id']
    
    # Busca o engagement pelo nome dentro do produto especificado
    engagement_endpoint = f"{url}/api/v2/engagements/"
    engagement_response = requests.get(
        engagement_endpoint,
        params={"name": engagement_name, "product": product_id},
        headers={"Authorization": f"Token {dojo_token}"},
        verify=False
    )
    engagements = engagement_response.json()
    
    if engagement_response.status_code != 200 or engagements['count'] == 0:
        sys.exit(f'Engagement não encontrado ou falha ao recuperar: {engagement_response.text}')
    
    return engagements['results'][0]['id']

def create_or_upload_test_based_on_count(dojo_token, url, product_name, engagement_name, filename):
    engagement_id = get_engagement_id_from_name(dojo_token, url, product_name, engagement_name)

    # Verifica a existência de testes com o scan_type 'SemGrep JSON Report' no engagement
    test_endpoint = f"{url}/api/v2/tests/"
    tests_response = requests.get(
        test_endpoint,
        params={"engagement": engagement_id},
        headers={"Authorization": f"Token {dojo_token}"},
        verify=False
    )
    if tests_response.status_code != 200:
        sys.exit(f'Falha ao recuperar testes: {tests_response.text}')

    tests_data = tests_response.json()
    semgrep_test_exists = any(test['test_type_name'] == "Semgrep JSON Report" for test in tests_data.get('results', []))
    
    if not semgrep_test_exists:
        # Se não existir um teste com 'Gitleaks', cria um novo teste
        print("Criando um novo teste com scan_type 'Semgrep JSON Report'.")
        new_test_data = {
            "engagement": engagement_id,
            "scan_type": "Semgrep JSON Report",
            "description": "Semgrep JSON Report",
            "target_start": "2024-03-27T01:02:02.253Z",
            "target_end": "2026-03-27T01:02:02.253Z",
            "percent_complete": 2147483647,
            "test_type": 120
        }
        create_test_response = requests.post(
            test_endpoint,
            headers={"Authorization": f"Token {dojo_token}"},
            data=new_test_data,
            verify=False
        )
        if create_test_response.status_code in [200, 201]:
            print("Novo teste criado com sucesso.")
        else:
            print(f"Falha ao criar novo teste: {create_test_response.text}")

    # Procede para importar o arquivo, agora que um teste apropriado existe ou foi criado
    uploadToDefectDojo(False, dojo_token, url, product_name, engagement_name, filename)

def uploadToDefectDojo(is_new_import, dojo_token, url, product_name, engagement_name, filename):

    endpoint = f"{url}/api/v2/import-scan/" if is_new_import else f"{url}/api/v2/reimport-scan/"
    headers= {'Authorization': 'Token ' + dojo_token}

    files = {
        'file': (filename, open(filename, 'rb'), "application/json")
    }

    data = {
        'scan_type': "Semgrep JSON Report",
        'product_name': product_name,
        'engagement_name': engagement_name,
        'product_type_name': 'Billing',
        'active': 'true',
        'environment': 'Lab',
        'do_not_reactivate': 'false',
        'skip_duplicates': 'true',
        'verified': 'true',
        'close_old_findings': 'true',
        'minimum_severity': 'Info'
    }

    r = requests.post(endpoint, headers=headers, files=files, data=data, verify=False)
    if r.status_code != 201:
        sys.exit(f'Falha ao importar scan: {r.text}')
    else:
        print(f'Report importado com sucesso: {r.text}')

if __name__ == "__main__":
    if len(sys.argv) == 9:
        product_name = sys.argv[2]
        engagement_name = sys.argv[4]
        report = sys.argv[6]
        dojo_token = sys.argv[8]
        create_or_upload_test_based_on_count(dojo_token, url, product_name, engagement_name, report)
    else:
        print('Uso: python3 semgrep.py --product NOME_DO_PRODUTO --engagement NOME_DO_ENGAGEMENT --report REPORT_SCAN --dojo_token TOKEN_DO_DOJO')