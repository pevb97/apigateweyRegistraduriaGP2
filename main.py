from flask import Flask
from flask import jsonify
from flask import request
from flask_cors import CORS
import json

from waitress import serve
import datetime
import requests
import re

app=Flask(__name__)
cors = CORS(app)

from flask_jwt_extended import create_access_token, verify_jwt_in_request
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager

app.config["JWT_SECRET_KEY"]="super-secret" #Cambiar por el que se conveniente
jwt = JWTManager(app)

@app.route("/login", methods = ["POST"])
def create_token():
        data = request.get_json()
        headers = {"Content-Type": "application/json; charset=utf-8"}
        url=dataConfig["url-backend-security"]+'/usuarios/validar'
        response = requests.post(url, json=data, headers=headers)
        if response.status_code == 200:
                user = response.json()
                expires = datetime.timedelta(seconds=60 * 60*24)
                access_token = create_access_token(identity=user, expires_delta=expires)
                return jsonify({"token": access_token, "user_id": user["_id"]})
        else:
                return jsonify({"msg": "Bad username or password"}), 401

@app.before_request
def before_request_callback():
    endPoint=limpiarURL(request.path)
    excludedRoutes=["/login"]
    if excludedRoutes.__contains__(request.path):
        pass

    elif verify_jwt_in_request():
        usuario = get_jwt_identity()

        if usuario["rol"]is not None:
            tienePersmiso=validarPermiso(endPoint,request.method,usuario["rol"]["_id"])
            if not tienePersmiso:
                return jsonify({"message": "Permission denied denegado"}), 401
        else:
            return jsonify({"message": "Permission denied"}), 401

def limpiarURL(url):
    partes = url.split("/")
    for laParte in partes:
        if re.search('\\d', laParte):
            url = url.replace(laParte, "?")
    return url

def validarPermiso(endPoint,metodo,idRol):
    url=dataConfig["url-backend-security"]+"/permisos-roles/validar-permiso/rol/"+str(idRol)
    tienePermiso=False
    headers = {"Content-Type": "application/json; charset=utf-8"}
    body={
        "url":endPoint,
        "metodo":metodo
    }
    response = requests.get(url, json=body, headers=headers)
    try:
            data = response.json()
            if ("_id" in data):
                    tienePermiso = True
    except:
            pass
    return tienePermiso

#////////////////////////////////////////////////////////////////////implemantacion redireccionamiento MESAS

@app.route("/mesas",methods=['POST'])
def crearMesa():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-registraduria-GP2"] + '/mesas'
    response = requests.post(url, headers=headers,json=data)
    json = response.json()
    return jsonify(json)

@app.route("/mesas",methods=['GET'])
def getMesas():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-registraduria-GP2"] + '/mesas'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/mesas/<string:id>",methods=['GET'])
def getMesa(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-registraduria-GP2"] + '/mesas/'+id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/mesas/<string:id>",methods=['PUT'])
def modificarMesa(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-registraduria-GP2"] + '/mesas/'+id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

@app.route("/mesas/<string:id>",methods=['DELETE'])
def eliminarMesas(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-registraduria-GP2"] + '/mesas/' + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)



#////////////////////////////////////////////////////////////////////implemantacion redireccionamiento PARTIDOS

@app.route("/partidos",methods=['POST'])
def crearPartido():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-registraduria-GP2"] + '/partidos'
    response = requests.post(url, headers=headers,json=data)
    json = response.json()
    return jsonify(json)

@app.route("/partidos",methods=['GET'])
def getPartidos():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-registraduria-GP2"] + '/partidos'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/partidos/<string:id>",methods=['GET'])
def getPartido(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-registraduria-GP2"] + '/partidos/'+id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/partidos/<string:id>",methods=['PUT'])
def modificarPartido(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-registraduria-GP2"] + '/partidos/'+id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

@app.route("/partidos/<string:id>",methods=['DELETE'])
def eliminarPartido(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-registraduria-GP2"] + '/partidos/' + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)


#////////////////////////////////////////////////////////////////////implemantacion redireccionamiento CANDIDATOS


@app.route("/candidatos",methods=['POST'])
def crearCandidato():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-registraduria-GP2"] + '/candidatos'
    response = requests.post(url, headers=headers,json=data)
    json = response.json()
    return jsonify(json)

@app.route("/candidatos",methods=['GET'])
def getCandidatos():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-registraduria-GP2"] + '/candidatos'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/candidatos/<string:id>",methods=['GET'])
def getCandidato(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-registraduria-GP2"] + '/candidatos/'+id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/candidatos/<string:id>",methods=['PUT'])
def modificarCandidato(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-registraduria-GP2"] + '/candidatos/'+id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

@app.route("/candidatos/<string:id>",methods=['DELETE'])
def eliminarCandidato(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-registraduria-GP2"] + '/candidatos/' + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)



#////////////////////////////////////////////////////////////////////implemantacion redireccionamiento RESOLUCIONES


@app.route("/resolucion",methods=['POST'])
def crearResolucion():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-registraduria-GP2"] + '/resolucion'
    response = requests.post(url, headers=headers,json=data)
    json = response.json()
    return jsonify(json)

@app.route("/resolucion",methods=['GET'])
def getResoluciones():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-registraduria-GP2"] + '/resolucion'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/resolucion/<string:id>",methods=['GET'])
def getResolucion(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-registraduria-GP2"] + '/resolucion/'+id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/resolucion/<string:id>",methods=['PUT'])
def modificarResolucion(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-registraduria-GP2"] + '/resolucion/'+id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

@app.route("/resolucion/<string:id>",methods=['DELETE'])
def eliminarResolucion(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-registraduria-GP2"] + '/resolucion/' + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)


#////////////////////////////////////////////////////////////////////implemantacion redireccionamiento VOTOS


@app.route("/votos",methods=['POST'])
def crearVoto():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-registraduria-GP2"] + '/voto'
    response = requests.post(url, headers=headers,json=data)
    json = response.json()
    return jsonify(json)

@app.route("/votos",methods=['GET'])
def getVotos():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-registraduria-GP2"] + '/voto'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/votos/<string:id>",methods=['GET'])
def getVoto(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-registraduria-GP2"] + '/voto/'+id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/votos/<string:id>",methods=['PUT'])
def modificarVoto(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-registraduria-GP2"] + '/voto/'+id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

@app.route("/votos/<string:id>",methods=['DELETE'])
def eliminarVoto(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-registraduria-GP2"] + '/voto/' + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)



#////////////////////////////////////////////////////////////////////implemantacion redireccionamiento REPORTES


@app.route("/reportes",methods=['POST'])
def crearReporte():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-registraduria-GP2"] + '/reportes'
    response = requests.post(url, headers=headers,json=data)
    json = response.json()
    return jsonify(json)


@app.route("/reportes/<string:id>",methods=['GET'])
def getReporte(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-registraduria-GP2"] + '/reportes/'+id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/reportes/<string:id>",methods=['PUT'])
def modificarReporte(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-registraduria-GP2"] + '/reportes/'+id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

@app.route("/reportes/<string:id>",methods=['DELETE'])
def eliminarReporte(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-registraduria-GP2"] + '/reportes/' + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)


#////////////////////////////////////////////////////////////////////implemantacion redireccionamiento RESULTADOS


@app.route("/resultados",methods=['POST'])
def crearResultado():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-registraduria-GP2"] + '/resultados'
    response = requests.post(url, headers=headers,json=data)
    json = response.json()
    return jsonify(json)


@app.route("/resultados/<string:id>",methods=['GET'])
def getResultado(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-registraduria-GP2"] + '/resultados/'+id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/resultados/<string:id>",methods=['PUT'])
def modificarResultado(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-registraduria-GP2"] + '/resultados/'+id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

@app.route("/resultados/<string:id>",methods=['DELETE'])
def eliminarResultado(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-registraduria-GP2"] + '/resultados/' + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)

#////////////////////////////////////////////////////////////////////implemantacion redireccionamiento arriba

@app.route("/",methods=['GET'])

def test():
        json = {}
        json["message"]="Server running en esta maqunina lenta..."
        return jsonify(json)

def loadFileConfig():
        with open('config.json') as f:
            data = json.load(f)
        return data

if __name__=='__main__':
        dataConfig = loadFileConfig()
        print("Server running : "+"http://"+dataConfig["url-backend"]+":" + str(dataConfig["port"]))
        serve(app, host =dataConfig["url-backend"], port =dataConfig["port"])