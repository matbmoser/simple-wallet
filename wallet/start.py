"""
This application is basically a mock from a wallet basic functionality of signing credentials without storing them.

The only thing that it will do is sign the credentials by using a private key and generate a signature that can be verified,
with a public key also generated.

"""

import sys
import os

# Add the previous folder structure to the system path to import the utilities
sys.path.append("../")

# Define flask imports and configuration
from flask import Flask, request, jsonify

app = Flask(__name__)

from rdflib import Graph

# Set up imports configuration
import argparse
import requests
import logging.config
import logging
from datetime import datetime
import traceback
from utilities.httpUtils import HttpUtils
from utilities.operators import op
from utilities.cryptool import cryptool
import yaml
from pyld import jsonld
import json
from passport import generator, parser


op.make_dir("logs")
op.make_dir("test")
# Load the config file
with open('./logging_config.yml', 'rt') as f:
    # Read the yaml configuration
    config = yaml.safe_load(f.read())
    # Set logging filename with datetime
    config["handlers"]["file"]["filename"] = f'logs/{op.get_filedatetime()}-wallet.log'
    logging.config.dictConfig(config)

# Configure the logging module with the config file


def get_arguments():
    """
    Commandline argument handling. Return the populated namespace.

    Returns:
        args: :func:`parser.parse_args`
    """
    
    parser = argparse.ArgumentParser()
    
    parser.add_argument("--port", default=7777, \
                        help="The server port where it will be available", required=False, type=int)
    
    parser.add_argument("--host", default="localhost", \
                        help="The server host where it will be available", required=False, type=str)
    
    parser.add_argument("--debug", default=False, action="store_true", \
                    help="Enable and disable the debug", required=False)
    
    args = parser.parse_args()
    return args


@app.get("/health")
def check_health():
    """
    Retrieves health information from the server

    Returns:
        response: :obj:`status, timestamp`
    """
    logger.debug("[HEALTH CHECK] Retrieving positive health information!")
    return jsonify({
        "status": "RUNNING",
        "timestamp": op.timestamp() 
    })


@app.post("/<bpn>/sign")
def sign_credential(bpn):
    """
    Signs a credential using the private key provided in the configuration

    Receives:
        vc: :vc: unsigned verifiable credential
    Returns:
        response: :vc: Signed verifiable credential
    """
    body = HttpUtils.get_body(request)
    
    if(not op.path_exists("./keys")):
        op.make_dir("keys")

    basePath = "./keys/"+bpn
    if(not op.path_exists(basePath)):
        op.make_dir(basePath)

    keyPath = "./keys/"+bpn

    privateKey = cryptool.generateJwkPrivateKey()
    return HttpUtils.response(cryptool.signVerifiableCredential(private_key=privateKey, data=body, issuer=bpn, id=cryptool.sha512(body)))

@app.get("/schema/<semanticIdHash>")
def schema(semanticIdHash):
    """
    Generates a context for the verifiable credentials

    Receives:
        vc: :vc: unsigned verifiable credential
    Returns:
        response: :vc: schema
    """
    try:
        filePath = f"./schemas/{semanticIdHash}/schema.json"
        if(not op.path_exists(filePath)):
           HttpUtils.get_error_response(message="Schema does not exist!", status=404)
        return HttpUtils.response(generator.schema_file_to_html(file_path=filePath), content_type="text/html")
    except Exception as e:
        logger.exception(e)
        traceback.print_exc()

    return HttpUtils.get_error_response(message="Error when parsing schema!")



@app.post("/parse")
def parse():
    """
    Generates a context for the verifiable credentials

    Receives:
        vc: :vc: unsigned verifiable credential
    Returns:
        response: :vc: schema
    """
    try:
        body = HttpUtils.get_body(request)
        
        semanticId = op.get_attribute(body, "semanticId")
        schema = op.get_attribute(body, "schema")
        aspectPrefix = op.get_attribute(body, "shortName")
        if not semanticId:
           HttpUtils.get_error_response(message="No semantic id specified", status=403)
        if not schema:
           HttpUtils.get_error_response(message="No schema specified", status=403)

        schemaParser = parser.sammSchemaParser()
        return HttpUtils.response(schemaParser.schema_to_jsonld(semanticId=semanticId, schema=schema, aspectPrefix=aspectPrefix))
    except Exception as e:
        logger.exception(e)
        traceback.print_exc()

    return HttpUtils.get_error_response(message="Error when parsing schema!")

@app.post("/expand")
def compact():
    """
    Generates a context for the verifiable credentials

    Receives:
        vc: :vc: unsigned verifiable credential
    Returns:
        response: :vc: schema
    """
    try:
        body = HttpUtils.get_body(request)
        return HttpUtils.response(jsonld.expand(body))
    except Exception as e:
        logger.exception(e)
        traceback.print_exc()

    return HttpUtils.get_error_response(message="Error when parsing schema!")


@app.post("/context")
def context():
    """
    Generates a context for the verifiable credentials

    Receives:
        vc: :vc: unsigned verifiable credential
    Returns:
        response: :vc: schema
    """
    try:
        body = HttpUtils.get_body(request)
        if(not body):
            return jsonify(HttpUtils.get_error_response())
        return HttpUtils.response(generator.schema_to_context(body))
    except Exception as e:
        logger.exception(e)
        traceback.print_exc()

    return HttpUtils.get_error_response(message="Error when parsing schema!")

@app.post("/ttl")
def ttl():
    """
    Generates a schema for the verifiable credentials

    Receives:
        vc: :vc: unsigned verifiable credential
    Returns:
        response: :vc: schema
    """
    try:
        body = HttpUtils.get_body(request)
        if(not body):
            return jsonify(HttpUtils.get_error_response())
        return HttpUtils.response(generator.turtle_to_jsonld(body))
    except Exception as e:
        logger.exception(e)
        traceback.print_exc()

    return HttpUtils.get_error_response(message="Error when parsing schema!")


if __name__ == '__main__':
    # Initialize the server environment and get the comand line arguments
    args = get_arguments()
    # Configure the logging configuration depending on the configuration stated
    logger = logging.getLogger('staging')
    if(args.debug):
        logger = logging.getLogger('development')
    # Start the flask application     
    app.run(host=args.host, port=args.port, debug=args.debug)
