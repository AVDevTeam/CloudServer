import ssl, requests, json, base64, os.path
from urllib.parse import urlparse
from http.server import BaseHTTPRequestHandler,HTTPServer
from ml_prediction import MLPredictor
import traceback
import sqlite3


import random, string
def rand_str():
    return ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(16))

class HttpProcessor(BaseHTTPRequestHandler):
    ml_predictor = MLPredictor()
    cachedb = sqlite3.connect('AVCache.db')

    def cuckoo_check_result(self, data):
        print('cuckoo_check_result')
        md5 = data['md5']
        cocukoo_r = requests.get(url=f'http://localhost:8090/files/view/md5/{md5}')
        if cocukoo_r.status_code != 200:
            return json.dumps({
                'action': 'cuckoo_check_result',
                'md5': md5,
                'status': 'not_found'
            }).encode('utf-8')
        fileid = cocukoo_r.json()['sample']['id']
        cocukoo_r = requests.get(url=f'http://localhost:8090/tasks/report/{fileid}')
        if cocukoo_r.status_code != 200:
            return json.dumps({
                'action': 'cuckoo_check_result',
                'md5': md5,
                'status': 'analysing'
            }).encode('utf-8')
        else:
            cuckoo_score = cocukoo_r.json()['info']['score']
            self.cachedb.execute('insert or ignore into AVCache (md5) values(?);', (md5,))
            self.cachedb.execute('update AVCache set cuckoo_score = ? where md5 = ?;', (cuckoo_score, md5))
            self.cachedb.commit()
            return json.dumps({
                'action': 'cuckoo_check_result',
                'md5': md5,
                'status': 'analysed',
                'cuckoo_score': str(cuckoo_score)
            }).encode('utf-8')

    def check_md5(self, data):
        print('check_md5')

        md5 = data['md5']
        result = self.cachedb.execute('SELECT ml_score, cuckoo_score FROM AVCache WHERE md5=?;', (md5,))
        rows = list(result)
        if len(rows) > 0:
            ml_score = rows[0][0] if rows[0][0] is not None else -1
            cuckoo_score = rows[0][1] if rows[0][1] is not None else -1
            print("1", md5, cuckoo_score,ml_score)
            return json.dumps({
                'action': 'check_md5',
                'md5': md5,
                'status': 'analysed',
                'cuckoo_score': str(cuckoo_score),
                'ml_score': str(ml_score)
            }).encode('utf-8')

        cuckoo_score, ml_score = -1, -1
        cocukoo_r = requests.get(url=f'http://localhost:8090/files/view/md5/{md5}')
        if cocukoo_r.status_code != 200:
            return json.dumps({
                'action': 'check_md5',
                'md5': md5,
                'status': 'not_found'
            }).encode('utf-8')
        cuckoo_info = cocukoo_r.json()
        print(cuckoo_info)
        fileid = cuckoo_info['sample']['id']
        sha256 = cuckoo_info['sample']['sha256']

        cocukoo_r = requests.get(url=f'http://localhost:8090/tasks/report/{fileid}')
        if cocukoo_r.status_code == 200:
            cuckoo_score = str(cocukoo_r.json()['info']['score'])

        local_file_path = "files/" + md5
        if os.path.isfile(local_file_path):
            ml_score = self.ml_predictor.classify(local_file_path)
        else:
            cocukoo_r = requests.get(url=f'http://localhost:8090/files/get/{sha256}')
            if cocukoo_r.status_code == 200 and int(self.headers.get('Content-Length')) > 0:
                file_payload = cocukoo_r.content
                with open(local_file_path, "wb") as f:
                    f.write(file_payload)
                ml_score = self.ml_predictor.classify(local_file_path)

        if (cuckoo_score != -1 or ml_score != -1):
            self.cachedb.execute('insert or replace into AVCache (md5, ml_score, cuckoo_score) values (?, ?, ?);', (md5, ml_score, cuckoo_score))
            self.cachedb.commit()
            print("2", cuckoo_score,ml_score)
            return json.dumps({
                'action': 'check_md5',
                'md5': md5,
                'status': 'analysed' if cuckoo_score != -1 else "analysing",
                'ml_score': str(ml_score),
                'cuckoo_score': str(cuckoo_score)
            }).encode('utf-8')

        return json.dumps({
            'action': 'check_md5',
            'md5': md5,
            'status': 'not_found'
        }).encode('utf-8')


    def analyse_file(self, data):
        print('analyse_file')

        file_payload = base64.b64decode(data['payload'])
        file_name = data['file_name']

        HEADERS = {"Authorization": "Bearer S4MPL3"}

        cuckoo_score = -1
        cocukoo_r = requests.get(url=f'http://localhost:8090/files/view/md5/{data["md5"]}')
        if cocukoo_r.status_code == 200:
            fileid = cocukoo_r.json()['sample']['id']
            cocukoo_r = requests.get(url=f'http://localhost:8090/tasks/report/{fileid}')
            if cocukoo_r.status_code == 200:
                cuckoo_score = cocukoo_r.json()['info']['score']

        if cuckoo_score == -1:
            files = {"file": (file_name, file_payload)}
            cocukoo_r = requests.post(url='http://localhost:8090/tasks/create/file', headers=HEADERS, files=files)

        local_file_path = "files/" + data['md5']
        with open(local_file_path, "wb") as f:
            f.write(file_payload)

        ml_score = self.ml_predictor.classify(local_file_path)
        print("ml_score", ml_score)

        md5 = data['md5']
        self.cachedb.execute('insert or ignore into AVCache (md5) values(?);', (md5,))
        self.cachedb.execute('update AVCache set ml_score = ? where md5 = ?;', (ml_score, md5))
        self.cachedb.commit()
        if cocukoo_r.status_code == 200:
            fileid = cocukoo_r.json()["task_id"]
        else:
            fileid = -1

        resp_json = json.dumps({
            'action': 'file_to_analyse',
            'md5': md5,
            'status': 'analysed' if cuckoo_score != -1 else "analysing",
            'cuckoo_score': str(cuckoo_score),
            'ml_score': str(ml_score)
        }).encode('utf-8')
        return resp_json

    def do_POST(self):
        try:
            content_len = int(self.headers.get('Content-Length'))
            data = json.loads(self.rfile.read(content_len))
            if (data['action'] == "check_md5"):
                resp_json = self.check_md5(data)
            elif (data['action'] == "analyse_file"):
                resp_json = self.analyse_file(data)
            elif (data['action'] == "cuckoo_check_result"):
                resp_json = self.cuckoo_check_result(data)

            self.send_response(200)
            self.end_headers()
            self.wfile.write(resp_json)
        except:
            traceback.print_exc()
            self.send_response(204)
            self.end_headers()


if __name__ == '__main__':
    httpd = HTTPServer(('0.0.0.0', 4443), HttpProcessor)
    httpd.socket = ssl.wrap_socket (httpd.socket, certfile='./server.pem', server_side=True)
    httpd.serve_forever()
