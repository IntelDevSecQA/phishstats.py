#
# phishstats.py
#
# Check phishstats API for keywors, ASN...
#
import sys
import requests
import re
import time
import sqlite3
import os.path

# Phishstats base url for API
base_url='https://phishstats.info:2096/api/phishing?_where='

# Phishstats earches
searches=[]

# Keywords to look after in search results
keywords=[]

# delay between two API calls
request_delay=1

# timeout for an API call
request_timeout=120

# print debug messages
debug=0

# Program logic blow this line

if len(sys.argv) < 2:
    print("Usage: phishstats.py [config file]")
    sys.exit(1)

config_file=sys.argv[1]

# Returns the parameter from the specified file
def get_config(parameter, file_path):
    # Check if secrets file exists
    if not os.path.isfile(file_path):
        print("ERROR: Config file (%s) not found"%file_path)
        sys.exit(0)

    # Find parameter in file
    with open( file_path ) as f:
        for line in f:
            if line.startswith( parameter ):
                return line.replace(parameter + ":", "").strip()

        # Cannot find parameter, exit
        print(file_path + "  Missing parameter %s "%parameter)
        sys.exit(0)
# enddef

# get param
searches=get_config("searches",config_file).split(',;,')
keywords=get_config("keywords",config_file).split(',;,')
db_file=get_config("db_file",config_file)

sql = sqlite3.connect(db_file)
db = sql.cursor()
db.execute('''CREATE TABLE IF NOT EXISTS phishstats (search text, phishing text)''')

#
# bool isKnown(json_data, search)
#
# true  json_data for search already known
# false entry not found
#
def isKnown(search, json_data):
    db.execute('SELECT * FROM phishstats WHERE search = ? AND phishing = ?', (search, str(json_data)))  # noqa
    last = db.fetchone()
    if last is None:
        return False
    return True
#enddef

def addPhishing(search, json_data):
    db.execute("INSERT INTO phishstats VALUES ( ? , ? )",(search,str(json_data)))
    sql.commit()
#enddef

def lookup(search,json_data):
    for key, value in json_data[0].items():
        for k in keywords:
            if k.lower() in str(value).lower():
                if not isKnown(search,json_data):
                    print("[NEW]",key, ":", value)
                    addPhishing(search,json_data)
                else:
                    #debug, print old entries too
                    if debug: print("[OLD]",key, ":", value)
#enddef

for search in searches:
    if debug: print("Searching for", search, "...", end='')
    try:
        response = requests.get(base_url + search, timeout=request_timeout)
        jsonResponse = response.json()
    except:
        print("ERROR: Request failed!",search)
        sys.exit(1)

    if debug: print("done.")
    if len(jsonResponse) > 0:
        lookup(search,jsonResponse)

    time.sleep(request_delay)


sys.exit(0)
# end
