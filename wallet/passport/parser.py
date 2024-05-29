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
    def __init__(self, semanticId="urn:samm:io.catenax.generic.digital_product_passport:5.0.0#"):
        self.baseSchema = dict()
        self.rootRef = "#"
        self.refKey = "$ref"
        self.pathSep = "/"
        self.propertiesKey = "properties"
        self.itemKey = "items"
        self.initialJsonLd = {
                "@version": 1.1,
                "type": "@type",
                "schema": "https://schema.org/",
                "aspect": semanticId,
        }
    
    def schema_to_jsonld(self, schema):
        self.baseSchema = copy.deepcopy(schema)
        if not self.propertiesKey in schema:
           raise Exception("Properties key not found in schema!")
        
        if "description" in schema:
            self.initialJsonLd["@definition"] = op.get_attribute(schema, "description") 

        self.initialJsonLd["@type"] = f"schema:{op.get_attribute(schema, "type")}"

        properties = op.get_attribute(sourceObject=schema, attrPath=self.propertiesKey)
        if not properties:
            raise Exception("It was not possible to get the properties attribute!")

        jsonLdContext = self.generate_properties(properties=properties, jsonLd=self.initialJsonLd) 
    
        if not jsonLdContext:
            raise Exception("It was not possible to generated the json-ld!")
        
        return {
            "@context": jsonLdContext
        }

    def generate_properties(self, properties, jsonLd):
        if not properties:
            return None
        
        jsonLd["id"] = "@id"
        jsonLd["type"] = "@type"

        for key, value in properties.items():
            jsonLd[key] = self.generate_property(key=key, property=value)
        
        return jsonLd
    
    def generate_property(self, key, property):

        newProperty = dict() 

        # If the property has a reference
        if self.refKey in property:
            oldProperty = self.get_schema_ref(obj=property)
        
        if not oldProperty:
            raise Exception("It was not possible to get the value of the property!")

        if not "type" in oldProperty:
            return None
        
        nodeType = op.get_attribute(oldProperty, "type")
        newProperty["@type"] = f"schema:{op.get_attribute(oldProperty, "type")}"
        
        if "id" in oldProperty:
            newProperty["@id"] = f"aspect:{key}"

        if "description" in oldProperty:
            newProperty["@definition"] = op.get_attribute(oldProperty, "description")

        if nodeType == "object":
            newProperty["id"] = "@id"
            props = op.get_attribute(sourceObject=oldProperty, attrPath=self.propertiesKey)
            if not props:
                raise Exception("It was not possible to generated the json-ld because properties of object were null!")
            context = self.generate_properties(properties=props, jsonLd=dict())
            if context:
               newProperty["@context"] = context
        
        if nodeType == "array":
            newProperty["@container"] = "@list"
            item = op.get_attribute(sourceObject=oldProperty, attrPath=self.itemKey)
            if not item:
                raise Exception("It was not possible to generated the json-ld because properties of object were null!")
            context = self.generate_item(item=item, itemKey=key, jsonLd=newProperty)
            if context:
               newProperty["@context"] = context

        return newProperty
        

    def generate_item(self, item, itemKey, jsonLd):
        
        if "type" in item:
            jsonLd["@type"] = f"schema:{op.get_attribute(item, "type")}"
            jsonLd["@id"] = f"aspect:{itemKey}"
            return jsonLd

        if not self.refKey in item:
            return None

        jsonLd["id"] = "@id"

        reference = self.get_schema_ref(obj=item)
        if not reference:
            raise Exception("The reference key was not found!")
        
        properties = op.get_attribute(sourceObject=reference, attrPath=self.propertiesKey)
        if not properties:
            raise Exception("The properties key was not found!")
        
        for key, property in properties.items():
            jsonLd[key] = self.generate_property(key=key, property=property)

        return jsonLd
    

    def get_schema_ref(self, obj):
        # Get reference key
        ref = op.get_attribute(obj, self.refKey)
        if(ref is None or not isinstance(ref, str)):
            print(f"Reference for obj [{obj}] not found or is not string")
            return None
        path = ref.removeprefix("#/")

        sub_schema = op.get_attribute(self.baseSchema, attrPath=path, pathSep=self.pathSep, defaultValue=None)
        if(sub_schema is None):
            print(f"Sub schema in path [{path}] not found!")
            return None
        
        return sub_schema

    """
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
        """
