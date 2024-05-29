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
import copy

class sammSchemaParser:
    def __init__(self, prefix):
        self.prefix = prefix
        self.baseSchema = dict()
        self.rootRef = "#"
        self.refKey = "$ref"
        self.pathSep = "/"
        self.propertiesKey = "properties"

    def simplify_schema(self, schema):
        self.baseSchema = copy.deepcopy(schema)
        return self.expand_properties(schema=schema)
    
    def expand_schema(self, schema):
        if not self.propertiesKey in schema:
            return schema
        
        properties = op.get_attribute(sourceObject=schema, attrPath=self.propertiesKey)
        if(properties is None or not properties):
            return schema
        
        return self.expand_properties(properties=properties)

    def expand_properties(self, properties):
        if not properties:
            return {}
        newProperties = dict()
        for key, property in properties:
            newProperties[key] = self.expand_property(property=property)
        
        return newProperties
        
    def expand_property(self, property):
        if not self.refKey in property:
            return property

        return self.get_schema_ref(property=property)

    def get_properties(self, schema):
        return
     
    def get_schema_ref(self, property):
        # Get reference key
        ref = op.get_attribute(property, self.refKey)
        if(ref is None or not isinstance(ref, str)):
            raise Exception(f"Reference for property [{property}] not found or is not string")
        path = ref.removeprefix("#")

        sub_schema = op.get_attribute(self.baseSchema, attrPath=path, pathSep=self.pathSep, defaultValue=None)
        if(sub_schema is None):
            raise Exception(f"Sub schema in path [{path}] not found!")
        return sub_schema
