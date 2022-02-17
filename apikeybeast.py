import argparse
import requests
import os
import sys

from rich.console import Console
from rich.table import Table
from rich.live import Live

console = Console()


def print_banner():
    print("""
 █████╗ ██████╗ ██╗██╗  ██╗███████╗██╗   ██╗██████╗ ███████╗ █████╗ ███████╗████████╗
██╔══██╗██╔══██╗██║██║ ██╔╝██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔════╝╚══██╔══╝
███████║██████╔╝██║█████╔╝ █████╗   ╚████╔╝ ██████╔╝█████╗  ███████║███████╗   ██║   
██╔══██║██╔═══╝ ██║██╔═██╗ ██╔══╝    ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██║╚════██║   ██║   
██║  ██║██║     ██║██║  ██╗███████╗   ██║   ██████╔╝███████╗██║  ██║███████║   ██║   
╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝   ╚═╝   
    """)
    print("\033[1mCoded by ValluvarSploit\033[0m\n")

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', '--service', dest="service", help='Display credit details of specified API service')
    parser.add_argument('-l', '--list', dest="list", action="store_true", help='List supported API services')
    args = parser.parse_args()

    if args.service is None and args.list is False:
        print_banner()
        parser.print_help()
        sys.exit(1)
    
    return args
    
ARGS = get_arguments()


def print_supported_services():
    list_api_table = Table(title="Supported API List", show_lines=True)
    list_api_table.add_column("Short form", no_wrap=True)
    list_api_table.add_column("Services", no_wrap=True)

    list_api_table.add_row('av', 'Alien Vault')
    list_api_table.add_row('bo', 'BufferOver')
    list_api_table.add_row('be', 'Binary Edge')
    list_api_table.add_row('bw', 'BuiltWith')
    list_api_table.add_row('cs', 'Censys')
    list_api_table.add_row('cp', 'Chaos Project Discovery')
    list_api_table.add_row('cf', 'Cloudflare')
    list_api_table.add_row('gh', 'Github')
    list_api_table.add_row('ht', 'hunter.io')
    list_api_table.add_row('ix', 'Intelx')
    list_api_table.add_row('id', 'IPdata')
    list_api_table.add_row('ii', 'IPinfo')
    list_api_table.add_row('nd', 'NetworkDB')
    list_api_table.add_row('op', 'Onyphe')
    list_api_table.add_row('pt', 'Passive Total')
    list_api_table.add_row('st', 'Security Trails')
    list_api_table.add_row('sd', 'Shodan')
    list_api_table.add_row('sh', 'Spamhaus')
    list_api_table.add_row('sp', 'Spyse')
    list_api_table.add_row('wx', 'WhoisXML API')
    list_api_table.add_row('ze', 'ZoomEye')

    console.print(list_api_table)

if ARGS.list:
    print_supported_services()
    sys.exit()
    

def create_table_skeleton():
    table = Table(title="API Key Credits Detail", caption="*cpm-credits per month and cpd-credits per day", caption_justify="left" ,show_lines=True)
    table.add_column("API", style="cyan", no_wrap=True)
    table.add_column("Products", no_wrap=True)
    table.add_column("Plan", no_wrap=True)
    table.add_column("Credits Left", style="green", no_wrap=True)
    table.add_column("Credits Total", no_wrap=True)
    table.add_column("Credits Used", no_wrap=True)
    table.add_column("Resets On", no_wrap=True)
    table.add_column("API Key", style="grey53")

    return table


def get_binary_edge_credits(table):
    binary_edge_username = os.environ.get("BINARY_EDGE_USERNAME")
    binary_edge_api_key = os.environ.get("BINARY_EDGE_API_KEY")

    response = requests.get(
        "https://api.binaryedge.io/v2/user/subscription", 
        headers={"X-Key":binary_edge_api_key,"Accept":"application/json"}
    )
    response_json = response.json()

    api_name = "Binary Edge"
    plan = response_json['subscription']['name']
    credits_left = response_json['requests_left']
    credits_total = response_json['requests_plan']
    credits_used = credits_total - credits_left
    credits_reset_date = response_json['end_date']
    product = ""

    table.add_row(
        api_name, 
        product, 
        plan, 
        str(credits_left), 
        f"{credits_total} cpm", 
        str(credits_used), 
        credits_reset_date, 
        f"username= {binary_edge_username}\nkey= {binary_edge_api_key}"
    )

def get_censys_credits(table):
    censys_username = os.environ.get("CENSYS_USERNAME")
    censys_api_id = os.environ.get("CENSYS_API_ID")
    censys_secret = os.environ.get("CENSYS_SECRET")

    response = requests.get(
        "https://search.censys.io/api/v1/account", 
        auth=(censys_api_id,censys_secret), 
        headers={"Accept":"application/json"}
    )
    response_json = response.json()

    api_name = "Censys"
    plan = "Free"
    credits_total = response_json['quota']['allowance']
    credits_used = response_json['quota']['used']
    credits_left = credits_total - credits_used
    credits_reset_date = response_json['quota']['resets_at']
    product = ""

    table.add_row(
        api_name, 
        product,
        plan, 
        str(credits_left), 
        f"{credits_total} cpm", 
        str(credits_used), 
        credits_reset_date, 
        f"username= {censys_username}\napi_id= {censys_api_id}\nsecret= {censys_secret}"
    )

def get_passive_total_credits(table):
    passive_total_username = os.environ.get("PASSIVE_TOTAL_USERNAME")
    passive_total_api_key = os.environ.get("PASSIVE_TOTAL_API_KEY")

    response = requests.get(
        "https://api.passivetotal.org/v2/account/quota", 
        auth=(passive_total_username, passive_total_api_key),
        headers={"Accept":"application/json"}
    )
    response_json = response.json()

    api_name = "Passive Total"
    plan = "Free"
    credits_total = response_json['user']['limits']['search_api']
    credits_used = response_json['user']['counts']['search_api']
    credits_left = credits_total - credits_used
    credits_reset_date = response_json['user']['next_reset']
    product = ""

    table.add_row(
        api_name, 
        product,
        plan, 
        str(credits_left), 
        f"{credits_total} cpm", 
        str(credits_used), 
        credits_reset_date, 
        f"username= {passive_total_username}\nkey= {passive_total_api_key}"
    )

def get_security_trails_credits(table):
    security_trails_username = os.environ.get("SECURITY_TRAILS_USERNNAME")
    security_trails_api_key = os.environ.get("SECURITY_TRAILS_API_KEY")

    response = requests.get(
        "https://api.securitytrails.com/v1/account/usage", 
        headers={"APIKEY":security_trails_api_key, "Accept":"application/json"}
    )
    response_json = response.json()

    api_name = "Security Trails"
    plan = "Free"
    credits_total = response_json['allowed_monthly_usage']
    credits_used = response_json['current_monthly_usage']
    credits_left = credits_total - credits_used
    credits_reset_date = "Monthly"
    product = ""

    table.add_row(
        api_name, 
        product,
        plan, 
        str(credits_left), 
        f"{credits_total} cpm", 
        str(credits_used), 
        credits_reset_date, 
        f"username= {security_trails_username}\nkey= {security_trails_api_key}"
    )

def get_shodan_credits(table):
    shodan_username = os.environ.get("SHODAN_USERNAME")
    shodan_api_key = os.environ.get("SHODAN_API_KEY")

    response = requests.get(
        "https://api.shodan.io/api-info?key="+shodan_api_key, 
        headers={"Accept":"application/json"}
    )
    response_json = response.json()

    api_name = "Shodan"
    plan = "Member"
    scan_credits_total = response_json['usage_limits']['scan_credits']
    scan_credits_left = response_json['scan_credits']
    scan_credits_used = scan_credits_total - scan_credits_left
    scan_credits_reset_date = "Monthly"
    product = "Scan"

    table.add_row(
        api_name, 
        product,
        plan, 
        str(scan_credits_left), 
        f"{scan_credits_total} cpm", 
        str(scan_credits_used), 
        scan_credits_reset_date, 
        f"username= {shodan_username}\nkey= {shodan_api_key}"
    )

    api_name = "Shodan"
    plan = "Member"
    query_credits_total = response_json['usage_limits']['query_credits']
    query_credits_left = response_json['query_credits']
    query_credits_used = query_credits_total - query_credits_left
    query_credits_reset_date = "Monthly"
    product = "Query"

    table.add_row(
        api_name, 
        product,
        plan, 
        str(query_credits_left), 
        f"{query_credits_total} cpm", 
        str(query_credits_used), 
        query_credits_reset_date, 
        f"username= {shodan_username}\nkey= {shodan_api_key}"
    )

    api_name = "Shodan"
    plan = "Member"
    monitor_credits_total = response_json['usage_limits']['monitored_ips']
    monitor_credits_used = response_json['monitored_ips']
    monitor_credits_left = monitor_credits_total - monitor_credits_used
    monitor_credits_reset_date = "Monthly"
    product = "Monitor"

    table.add_row(
        api_name, 
        product, 
        plan, 
        str(monitor_credits_left), 
        f"{monitor_credits_total} cpm", 
        str(monitor_credits_used), 
        monitor_credits_reset_date, 
        f"username= {shodan_username}\nkey= {shodan_api_key}"
    )

def get_newtworkdb_credits(table):
    networksdb_username = os.environ.get("NETWORKS_DB_USERNAME")
    networksdb_api_key = os.environ.get("NETWORKS_DB_API_KEY")

    response = requests.get(
        "https://networksdb.io/api/key", 
        headers={"X-Api-Key":networksdb_api_key,"Accept":"application/json"}
    )
    response_json = response.json()

    api_name = "Networks DB"
    plan = response_json['type']
    credits_total = response_json['req_limit']
    credits_used = response_json['req_count']
    credits_left = response_json['req_left']
    credits_reset_date = response_json['resets_at']
    product = ""

    table.add_row(
        api_name, 
        product, 
        plan.title(), 
        str(credits_left), 
        f"{credits_total} cpm", 
        str(credits_used), 
        credits_reset_date, 
        f"username= {networksdb_username}\nkey= {networksdb_api_key}"
    )

def get_whoisxmlapi_credits(table):
    whoisxmlapi_username = os.environ.get("WHOIS_XML_API_USERNAME")
    whoisxmlapi_api_key = os.environ.get("WHOIS_XML_API_KEY")

    response = requests.get(
        "https://user.whoisxmlapi.com/service/account-balance?apiKey="+whoisxmlapi_api_key, 
        headers={"Accept":"application/json"}
    )
    response_json = response.json()

    api_name = "Whois XML API"

    for i in range(12):
        plan = "Free"
        product = response_json['data'][i]['product']['name']
        credits_left = response_json['data'][i]['credits']
        credits_total = "Undefined"
        credits_used = "Undefined"
        credits_reset_date = "Undefined"

        table.add_row(
            api_name, 
            product,
            plan, 
            str(credits_left),
            f"{credits_total} cpm",
            credits_used,
            credits_reset_date, 
            f"username= {whoisxmlapi_username}\nkey= {whoisxmlapi_api_key}"
        )

def get_zoomeye_credits(table):
    zoomeye_username = os.environ.get("ZOOMEYE_USERNAME")
    zoomeye_password = os.environ.get("ZOOMEYE_PASSWORD")

    login = requests.post(
        "https://api.zoomeye.org/user/login", 
        json={"username":zoomeye_username,"password":zoomeye_password},
        headers={"Accept":"application/json"}
    )
    login_json = login.json()
    jwt_access_token = login_json['access_token']

    response = requests.get(
        "https://api.zoomeye.org/resources-info", 
        headers={"Authorization":f"JWT {jwt_access_token}","Accept":"application/json"})
    response_json = response.json()

    api_name = "ZoomEye"
    plan = response_json['plan']
    credits_total = response_json['quota_info']['remain_total_quota']
    credits_left = response_json['quota_info']['remain_free_quota']
    credits_used = credits_total - credits_left
    credits_reset_date = "Monthly"
    product = ""

    table.add_row(
        api_name, 
        product,
        plan.title(), 
        str(credits_left), 
        f"{credits_total} cpm", 
        str(credits_used), 
        credits_reset_date, 
        f"Username= {zoomeye_username}\nPassword= {zoomeye_password}"
    )

def get_urlscan_credits(table):
    urlscanio_username = os.environ.get("URLSCANIO_USERNAME")
    urlscanio_api_key = os.environ.get("URLSCANIO_API_KEY")

    response = requests.get("https://urlscan.io/user/quotas", headers={"API-Key":urlscanio_api_key, "Content-Type":"application/json"})
    response_json = response.json()
    print(response_json)

    api_name = "URLScanIO"
    plan = "Free"
    credits_total = response_json['search']['day']['limit']
    credits_used = response_json['search']['day']['used']
    credits_left = response_json['search']['day']['remaining']
    credits_reset_date = response_json['search']['day']['reset']

    table.add_row(
        api_name, 
        plan, 
        str(credits_left), 
        f"{credits_total} cpm", 
        str(credits_used), 
        credits_reset_date, 
        f"username= {urlscanio_username}\nkey= {urlscanio_api_key}"
    )

def get_alienvault_credits(table):
    alien_vault_username = os.environ.get("ALIEN_VALUT_USERNAME")
    alien_valut_api_key = os.environ.get("ALIEN_VAULT_API_KEY")

    response = requests.get(
        "https://otx.alienvault.com/api/v1/user/me", 
        headers={"X-OTX-API-KEY":alien_valut_api_key,"Accept":"application/json"}
    )
    response_json = response.json()

    api_name = "Alien Valult"
    plan = "Free"
    credits_total = "Undefined"
    credits_left = "Undefined"
    credits_used = "Undefined"
    credits_reset_date = "Undefined"
    product = ""

    table.add_row(
        api_name, 
        product,
        plan, 
        str(credits_left), 
        f"{credits_total} cpm", 
        str(credits_used), 
        str(credits_reset_date), 
        f"username= {alien_vault_username}\nkey= {alien_valut_api_key}"
    )

def get_bufferoverrun_credits(table):
    bufferoverrun_username = os.environ.get("BUFFEROVERRUN_USERNAME")
    bufferoverrun_api_key = os.environ.get("BUFFEROVERRUN_API_KEY")

    api_name = "BufferOver"
    plan = "Free"
    credits_total = "Undefined"
    credits_left = "Undefined"
    credits_used = "Undefined"
    credits_reset_date = "Undefined"
    product = ""

    table.add_row(
        api_name,
        product,
        plan, 
        str(credits_left), 
        f"{credits_total} cpm", 
        str(credits_used), 
        credits_reset_date, 
        f"username= {bufferoverrun_username}\nkey= {bufferoverrun_api_key}"
    )

def get_builtwith_credits(table):
    builtwith_username = os.environ.get("BUILT_WITH_USERNAME")
    builtwith_api_key = os.environ.get("BUILT_WITH_API_KEY")

    response = requests.get(
        "https://api.builtwith.com/usagev2/api.json", 
        params={"KEY":builtwith_api_key}, 
        headers={"Accept":"application/json"}
    )
    response_json = response.json()

    api_name = "BuiltWith"
    plan = "Free"
    credits_total = response_json['purchased']
    credits_used = response_json['used']
    credits_left = response_json['remaining']
    credits_reset_date = "Undefined"
    product = ""

    table.add_row(
        api_name, 
        product, 
        plan, 
        str(credits_left), 
        f"{credits_total} cpm", 
        str(credits_used), 
        str(credits_reset_date), 
        f"username= {builtwith_username}\nkey= {builtwith_api_key}"
    )

def get_chaos_pd_credits(table):
    chaos_pd_username = os.environ.get("CHAOS_USERNAME")
    chaos_pd_api_key = os.environ.get("CHAOS_KEY")

    api_name = "Chaos PD"
    plan = "Full"
    credits_total = "Undefined"
    credits_left = "Undefined"
    credits_used = "Undefined"
    credits_reset_date = "Undefined"
    product = ""

    table.add_row(
        api_name, 
        product, 
        plan, 
        str(credits_left), 
        f"{credits_total} cpm", 
        str(credits_used), 
        str(credits_reset_date), 
        f"username= {chaos_pd_username}\nkey= {chaos_pd_api_key}"
        )

def get_cloudflare_credits(table):
    cloudflare_username = os.environ.get("CLOUDFLARE_USERNAME")
    cloudflare_api_key = os.environ.get("CLOUDFLARE_API_KEY")

    api_name = "Cloudflare"
    plan = "Free"
    credits_total = "Undefined"
    credits_left = "Undefined"
    credits_used = "Undefined"
    credits_reset_date = "Undefined"
    product = ""

    table.add_row(
        api_name, 
        product, 
        plan, 
        str(credits_left), 
        f"{credits_total}", 
        str(credits_used), 
        str(credits_reset_date), 
        f"username= {cloudflare_username}\nkey= {cloudflare_api_key}"
    )

def get_github_credits(table):
    github_username = os.environ.get("GITHUB_USERNAME")
    github_api_key = os.environ.get("GITHUB_TOKEN")

    response = requests.get(
        "https://api.github.com/user", 
        auth=(github_username, github_api_key), 
        headers={"Accept":"application/json"}
    )
    response_json = response.json()

    api_name = "Github"
    plan = "Free"
    credits_total = "Undefined"
    credits_left = "Undefined"
    credits_used = "Undefined"
    credits_reset_date = "Undefined"
    # api_key_expires_on = response.headers['github-authentication-token-expiration']
    product = ""

    table.add_row(
        api_name, 
        product, 
        plan, 
        str(credits_left), 
        f"{credits_total} cpm", 
        str(credits_used), 
        str(credits_reset_date), 
        f"username= {github_username}\nkey= {github_api_key}"
    )

def get_hunter_credits(table):
    hunter_api_key = os.environ.get("HUNTER_API_KEY")

    response = requests.get(
        "https://api.hunter.io/v2/account", 
        params={"api_key":hunter_api_key},
        headers={"Accept":"application/json"}
    )
    response_json = response.json()

    api_name = "Hunter"
    hunter_username = response_json['data']['email']
    plan = response_json['data']['plan_name']
    credits_total = response_json['data']['requests']['searches']['available']
    credits_used = response_json['data']['requests']['searches']['used']
    credits_left = credits_total - credits_used
    credits_reset_date = response_json['data']['reset_date']
    product = ""

    table.add_row(
        api_name, 
        product,
        plan, 
        str(credits_left), 
        f"{credits_total} cpm", 
        str(credits_used), 
        str(credits_reset_date), 
        f"username= {hunter_username}\nkey= {hunter_api_key}"
    )

def get_intelx_credits(table):
    intelx_username = os.environ.get('INTELX_USERNAME')
    intelx_api_key = os.environ.get('INTELX_API_KEY')

    response = requests.get(
        "https://2.intelx.io/authenticate/info", 
        headers={"x-key":intelx_api_key,"User-Agent":"IX-Python/0.5", "Accept":"application/json"}
    )
    response_json = response.json()
    product_paths = response_json['paths']

    api_name = "IntelX"
    plan = "Academia"
    local_product_path = ['/file/preview','/file/read','/file/view','/intelligent/search','/intelligent/search/export','/phonebook/search']

    for key, value in product_paths.items():
        if key in local_product_path:
            if value['Path'] == "/file/preview":
                product = "File Preview"
            elif value['Path'] == "/file/read":
                product = "File Read"
            elif value['Path'] == "/file/view":
                product = "File View"
            elif value['Path'] == "/intelligent/search":
                product = "Search"
            elif value['Path'] == "/intelligent/search/export":
                product = "Search Export"
            elif value['Path'] == "/phonebook/search":
                product = "Phonebook Search"
                
            credits_total = value['CreditMax']
            credits_left = value['CreditMax']
            credits_used = credits_total - credits_left
            credits_reset_date = "Monthly"
            
            table.add_row(
                api_name, 
                product, 
                plan, 
                str(credits_left), 
                f"{credits_total} cpm", 
                str(credits_used), 
                str(credits_reset_date), 
                f"username= {intelx_username}\nkey= {intelx_api_key}"
            )

def get_ipdata_credits(table):
    ipdata_username = os.environ.get("IPDATA_USERNAME")
    ipdata_api_key = os.environ.get("IPDATA_API_KEY")

    api_name = "IPdata"
    plan = "Free"
    credits_total = "1500"
    credits_used = "Undefined"
    credits_left = "Undefined"
    credits_reset_date = "Daily"
    product = ""

    table.add_row(
        api_name, 
        product, 
        plan, 
        str(credits_left), 
        f"{credits_total} cpm", 
        str(credits_used), 
        credits_reset_date, 
        f"username= {ipdata_username}\nkey= {ipdata_api_key}"
    )

def get_ipinfo_credits(table):
    ipinfo_username = os.environ.get("IPINFO_USERNAME")
    ipinfo_api_key = os.environ.get("IPINFO_API_KEY")

    response = requests.get(
        "https://ipinfo.io/me", 
        params={"token":ipinfo_api_key}, 
        headers={"Accept":"application/json"}
    )
    response_json = response.json()

    api_name = "IPinfo"
    plan = "Free"
    credits_total = response_json['requests']['limit']
    credits_used = response_json['requests']['month']
    credits_left = response_json['requests']['remaining']
    credits_reset_date = "Monthly"
    product = ""

    table.add_row(
        api_name, 
        product, 
        plan, 
        str(credits_left), 
        f"{credits_total} cpm", 
        str(credits_used), 
        str(credits_reset_date), 
        f"username= {ipinfo_username}\nkey= {ipinfo_api_key}"
    )

def get_onyphe_credits(table):
    onyphe_username = os.environ.get("ONYPHE_USERNAME")
    onyphe_api_key = os.environ.get("ONYPHE_API_KEY")

    response = requests.get("https://www.onyphe.io/api/v2/user", headers={"Authorization":f"apikey {onyphe_api_key}","Content-Type":"application/json"})
    response_json = response.json()

    api_name = "Onyphe"
    plan = "Free"
    credits_total = 250
    credits_left = response_json['results'][0]['credits']
    credits_used = credits_total - credits_left
    credits_reset_date = "Undefined"
    product = ""

    table.add_row(
        api_name, 
        product, 
        plan, 
        str(credits_left), 
        f"{credits_total} cpm", 
        str(credits_used), 
        credits_reset_date, 
        f"username= {onyphe_username}\nkey= {onyphe_api_key}"
    )

def get_spamhaus_credits(table):
    spamhaus_username = os.environ.get("SPAMHAUS_USERNAME")
    spamhaus_password = os.environ.get("SPAMHAUS_PASSSWORD")

    login = requests.post(
        "https://api-pdns.spamhaustech.com/v2/login?pretty", 
        json={"username":spamhaus_username,"password":spamhaus_password}, 
        headers={"Content-Type":"application/json"}
    )
    login_json = login.json()
    jwt_access_token = login_json["token"]

    response = requests.get(
        "https://api-pdns.spamhaustech.com/v2/limits", 
        headers={"Authorization":f"Bearer {jwt_access_token}","Accept":"application/json"}
    )
    response_json = response.json()

    api_name = "Spamhaus"
    plan = "Free"
    credits_month_total = response_json['limits']['qpm']
    credits_month_used = response_json['current']['qpm']
    credits_month_left = credits_month_total - credits_month_used

    credits_day_total = response_json['limits']['qpd']
    credits_day_used = response_json['current']['qpd']
    credits_day_left = credits_day_total - credits_day_used
    credits_reset_date = "Undefined"
    product = ""

    table.add_row(
        api_name, 
        product, 
        plan, 
        f"{credits_month_left}\n{credits_day_left}", 
        f"{credits_month_total} cpm\n{credits_day_total} cpd", 
        f"{credits_month_used}\n{credits_day_used}", 
        credits_reset_date,
        f"Username={spamhaus_username}\nPassword={spamhaus_password}"
    )
    
def get_spyse_credits(table):
    spyse_username = os.environ.get("SPYSE_USERNAME")
    spyse_api_key = os.environ.get("SPYSE_API_KEY")

    response = requests.get(
        "https://api.spyse.com/v4/data/account/quota", 
        headers={"Authorization":f"Bearer {spyse_api_key}","Accept":"application/json"}
    )
    response_json = response.json()

    api_name = "Spyse"
    plan = "Free"
    credits_month_total = response_json['data']['items'][0]['api_requests_limit']
    credits_month_left = response_json['data']['items'][0]['api_requests_remaining']
    credits_month_used = credits_month_total - credits_month_left
    credits_resets_on = response_json['data']['items'][0]['end_at']
    product = ""

    table.add_row(
        api_name, 
        product, 
        plan, 
        str(credits_month_left), 
        f"{credits_month_total} cpm", 
        str(credits_month_used), 
        credits_resets_on,
        f"username= {spyse_username}\nkey= {spyse_api_key}"
    )
    

def main():
    table = create_table_skeleton()
    with Live(table, console=console, screen=False, refresh_per_second=20):
        if ARGS.service == 'av':
            get_alienvault_credits(table)
        elif ARGS.service == 'bo':
            get_bufferoverrun_credits(table)
        elif ARGS.service == 'be':
            get_binary_edge_credits(table)
        elif ARGS.service == 'bw':
            get_builtwith_credits(table)
        elif ARGS.service == 'cs':
            get_censys_credits(table)
        elif ARGS.service == 'cp':
            get_chaos_pd_credits(table)
        elif ARGS.service == 'cf':
            get_cloudflare_credits(table)
        elif ARGS.service == 'gh':
            get_github_credits(table)
        elif ARGS.service == 'ht':
            get_hunter_credits(table)
        elif ARGS.service == 'ix':
            get_intelx_credits(table)
        elif ARGS.service == 'id':
            get_ipdata_credits(table)
        elif ARGS.service == 'ii':
            get_ipinfo_credits(table)
        elif ARGS.service == 'nd':
            get_newtworkdb_credits(table)
        elif ARGS.service == 'op':
            get_onyphe_credits(table)
        elif ARGS.service == 'pt':
            get_passive_total_credits(table)
        elif ARGS.service == 'st':
            get_security_trails_credits(table)
        elif ARGS.service == 'sd':
            get_shodan_credits(table)
        elif ARGS.service == 'sh':
            get_spamhaus_credits(table)
        elif ARGS.service == 'sp':
            get_spyse_credits(table)
        # get_urlscan_credits(table)  # Need to work on
        elif ARGS.service == 'wx':
            get_whoisxmlapi_credits(table)
        elif ARGS.service == 'ze':
            get_zoomeye_credits(table)
        elif ARGS.service == 'all':
            get_alienvault_credits(table)
            get_bufferoverrun_credits(table)
            get_binary_edge_credits(table)
            get_builtwith_credits(table)
            get_censys_credits(table)
            get_chaos_pd_credits(table)
            get_cloudflare_credits(table)
            get_github_credits(table)
            get_hunter_credits(table)
            get_intelx_credits(table)
            get_ipdata_credits(table)
            get_ipinfo_credits(table)
            get_newtworkdb_credits(table)
            get_onyphe_credits(table)
            get_passive_total_credits(table)
            get_security_trails_credits(table)
            get_shodan_credits(table)
            get_spamhaus_credits(table)
            get_spyse_credits(table)
        # get_urlscan_credits(table)  # Need to work on
            get_whoisxmlapi_credits(table)
            get_zoomeye_credits(table)
        else:
            print("Request API is not supported")


if __name__ == "__main__":
    main()
