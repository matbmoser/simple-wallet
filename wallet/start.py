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


# Set up imports configuration
import argparse
import requests
import logging.config
import logging
from datetime import datetime
import traceback
from logging.config import fileConfig
from utilities.httpUtils import httpUtils
from utilities.operators import op
import yaml

op.make_dir("logs")

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


@app.post("/sign")
def sign_credential():
    """
    Signs a credential using the private key provided in the configuration

    Returns:
        response: :vc: Signed verifiable credential
    """
    body = request.body
    if(not body):
       return jsonify(HttpUtils.get_error_response())
    
    logger.debug("[] Credential Signed!")
    return jsonify(body)


if __name__ == '__main__':
    # Initialize the server environment and get the comand line arguments
    args = get_arguments()
    # Configure the logging configuration depending on the configuration stated
    logger = logging.getLogger('staging')
    if(args.debug):
        logger = logging.getLogger('development')
    # Start the flask application     
    app.run(host=args.host, port=args.port, debug=args.debug)
