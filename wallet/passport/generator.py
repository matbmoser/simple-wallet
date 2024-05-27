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
import yaml
from pyld import jsonld
import json
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012
from json_schema_for_humans.generate import generate_from_schema
from json_schema_for_humans.generation_configuration import GenerationConfiguration

config = GenerationConfiguration(copy_css=False, expand_buttons=True)

def turtle_to_jsonld(data, file_path=None):
    g = Graph()
    g.parse(data=data,format='turtle')
    response = g.serialize(format='json-ld')
    response = json.loads(response)
    if(file_path is not None):
        op.to_json_file(response, "test/schema.json")
    return response

def schema_to_context(data, file_path=None):
    description= op.get_attribute(data, "description")
    print(description)
    resolver = op.get_attribute(data, "properties")
    print(resolver)
    return resolver


def schema_to_html(data, file_path=None):
    resolver = generate_from_schema(schema_file="./",loaded_schemas=op.json_string_to_object(op.to_json(data)), config=config)
    return resolver

def schema_file_to_html(file_path):
    resolver = generate_from_schema(schema_file=file_path, config=config)
    return resolver