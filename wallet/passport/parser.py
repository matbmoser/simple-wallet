import sys
import os
# Add the previous folder structure to the system path to import the utilities
sys.path.append("../../")

# Define flask imports and configuration
from flask import Flask, request, jsonify

app = Flask(__name__)

from rdflib import Graph
import pprint
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

#urn:samm:io.catenax.single_level_bom_as_built:3.0.0#

class sammSchemaParser:
    def __init__(self):
        self.baseSchema = dict()
        self.rootRef = "#"
        self.refKey = "$ref"
        self.pathSep = "#/"
        self.actualPathSep = "/-/"
        self.refPathSep="/"
        self.propertiesKey = "properties"
        self.itemKey = "items"
        self.schemaPrefix = "schema"
        self.aspectPrefix = "aspect"
        self.contextPrefix = "@context"
        self.complexTypes = ["object", "array"]
        self.parentRefs=list()
        self.parentRef = None
        self.recursionDepth = 2
        self.depht = 0
        self.initialJsonLd = {
            "@version": 1.1,
            self.schemaPrefix: "https://schema.org/"
        }
        self.contextTemplate = {
            "@version": 1.1,
            "id": "@id",
            "type": "@type"
        }
    
    def schema_to_jsonld(self, semanticId, schema, aspectPrefix="aspect"):
        try:
            self.baseSchema = copy.copy(schema)
            semanticParts = semanticId.split(self.rootRef)  
            if((len(semanticParts) < 2) or (semanticParts[1] == '')):
                raise Exception("Invalid semantic id, missing the model reference!")
            
            if not(aspectPrefix is None):
                self.aspectPrefix = aspectPrefix

        
            jsonLdContext = self.create_node(property=schema)
            
            if jsonLdContext is None:
                raise Exception("It was not possible to generated the json-ld!")
            
            responseContext = copy.copy(self.initialJsonLd)

            semanticPath = semanticParts[0]
            responseContext[self.aspectPrefix] = semanticPath + self.rootRef
            aspectName = semanticParts[1]
            jsonLdContext["@id"] = ":".join([self.aspectPrefix,aspectName])
            responseContext[aspectName] = jsonLdContext
            
            if "description" in schema:
                responseContext[aspectName]["@context"]["@definition"] = schema["description"]
            return {
                "@context": responseContext
            }
        except:
            traceback.print_exc()
            raise Exception("It was not possible to create jsonld schema")
    

    def expand_node(self, ref, actualref, key=None):
        try:
            ## Ref must not be None
            if (ref is None): return None
            ## Get expanded node
            expandedNode = self.get_schema_ref(ref=ref, actualref=actualref)

            newRef = self.actualPathSep.join([actualref, ref])

            if(expandedNode is None): return None
            return self.create_node(property=expandedNode, actualref=newRef, key=key)
        except:
            traceback.print_exc()
            print("It was not possible to expand the node")
            return None

    def create_node(self, property, actualref="", key=None):
        try:
            ## Schema must be not none and type must be in the schema
            if (property is None) or (not "type" in property): return None
            
            ## Start by creating a simple node
            node = self.create_simple_node(property=property, key=key)

            ## If is not possible to create the simple node it is not possible to create any node
            if(node is None): return None

            propertyType = property["type"]

            if propertyType == "object":
                return self.create_object_node(property=property, node=node, actualref=actualref)
            
            if propertyType == "array":
                return self.create_array_node(property=property, node=node, actualref=actualref)
            
            return self.create_value_node(property=property, node=node)
        except:
            traceback.print_exc()
            print("It was not possible to create the node")
            return None

    def create_value_node(self, property, node):
        try:
            ## If type exists add definition to the node
            if not ("type" in property): return None
            
            node["@type"] = self.schemaPrefix+":"+property["type"]
            return node
        except:
            traceback.print_exc()
            print("It was not possible to create value node")
            return None
    
    def create_object_node(self, property, node, actualref):
        try:
            ## If object has not the properties key
            if not (self.propertiesKey in property): return None
            
            properties = property[self.propertiesKey]

            node[self.contextPrefix] = self.create_properties_context(properties=properties, actualref=actualref)
            return node
        except:
            traceback.print_exc()
            print("It was not possible to create object node")
            return None

    def create_array_node(self, property, node, actualref=None):
        try:
            ## If array node has not the item key
            if not (self.itemKey in property): return None
            
            item = property[self.itemKey]
            node["@container"] = "@list" 

            ## If list is with different types of data, dont specify a type
            if(isinstance(item, list)):
                return node

            if not (self.refKey in item):
                return self.create_value_node(property=item, node=node)

            node[self.contextPrefix] = self.create_item_context(item=item, actualref=actualref)
            return node
        except:
            traceback.print_exc()
            print("It was not possible to create the array node")
            return None

    
    
    def filter_key(self, key):
        cleanKey = key
        if ("@" in key): 
            cleanKey = key.replace("@","")
        
        if (" " in key): 
            cleanKey = key.replace(" ","-")
        return cleanKey


    def create_properties_context(self, properties, actualref):
        try:
            ## If no key is provided or node is empty
            if(properties is None): return None
            
            ## If no key is found
            if(not isinstance(properties, dict)): return None
            
            ## If no keys are provided in the properties
            if(len(properties.keys())  == 0): return None
            
            ## Create new context dict from template
            newContext = copy.copy(self.contextTemplate)
            oldProperties = copy.copy(properties)

            ## Fill the node context with the properties
            for propKey, prop in oldProperties.items():
                key = self.filter_key(key=propKey)
                prop = self.create_node_property(key=key, node=prop, actualref=actualref)
                if (prop is None):
                    continue
                

                newContext[key] = prop

            ## Add context properties to the node context
            return newContext
        except:
            traceback.print_exc()
            print("It was not possible to create properties context")
            return None
        
    def create_item_context(self, item, actualref):
        try:
            ## If no key is provided or node is empty
            if(item is None): return None
            
            newContext = copy.copy(self.contextTemplate)
            ref = item[self.refKey]
            nodeItem = self.expand_node(ref=ref, actualref=actualref)

            ## If was not possible to get the reference return None
            if nodeItem is None: return None

            newContext.update(nodeItem)
            ## Overite the existing description of ref item

            if not ("description" in item):
                return newContext
            
            if not ("@context" in newContext):
                newContext["@context"] = dict()

            newContext["@context"]["@definition"]  = item["description"] 

            return newContext
        except:
            traceback.print_exc()
            print("It was not possible to create the item context")
            return None
        
    def create_node_property(self, key, node, actualref):
        try:
            ## If no key is provided or node is empty
            if(key is None) or (node is None): return None

            ## Ref property must exist in a property inside properties
            if not (self.refKey in node): return None

            ## Get reference from the base schema
            ref = node[self.refKey]
            nodeProperty = self.expand_node(ref=ref, actualref=actualref, key=key)

            ## If was not possible to get the reference return None
            if nodeProperty is None: return None

            ## Overite the existing description of ref property
            if not ("description" in node):
                return nodeProperty
            
            if not ("@context" in nodeProperty):
                nodeProperty["@context"] = dict()

            nodeProperty["@context"]["@definition"]  = node["description"]

            return nodeProperty
        except:
            traceback.print_exc()
            print("It was not possible to create node property")
            return None


    def create_simple_node(self, property, key=None):
        """
        Creates a simple node with key and object from a schema property
        Receives:
            key: :str: attribute key
            node: :dict: contains the node object with or without description and type
        Returns:
            response: :dict: json ld simple node with the information of the node object
        """
        try:
            ## If no key is provided or node is empty
            if (property is None): return None
            
            ## Create new json ld simple node
            newNode = dict()

            ## If the key is not none create a new node
            if not (key is None):
                newNode["@id"] = self.aspectPrefix+":"+key
            

            ## If description exists add definition to the node

            if not ("description" in property):
                return newNode
            
            if not ("@context" in newNode):
                newNode["@context"] = dict()

            newNode["@context"]["@definition"] = property["description"]

            return newNode
        except:
            traceback.print_exc()
            print("It was not possible to create the simple node")
            return None

    def get_schema_ref(self, ref, actualref):
        """
        Creates a simple node with key and object from a schema property
        Receives:
            key: :str: attribute key
            node: :dict: contains the node object with or without description and type
        Returns:
            response: :dict: json ld simple node with the information of the node object
        """
        try:
            if(not isinstance(ref, str)): return None
            
            # If the actual reference is already found means we are going in a loop
            if not(ref in actualref):     
                path = ref.removeprefix(self.pathSep) 
                return op.get_attribute(self.baseSchema, attrPath=path, pathSep=self.refPathSep, defaultValue=None)
            
            if(self.depht >= self.recursionDepth):
                print(f"[WARNING] Infinite recursion detected in the following path: ref[{ref}] and acumulated ref[{actualref}]!")
                self.depht=0
                return None
            
            self.depht+=1
            
            path = ref.removeprefix(self.pathSep) 

            return op.get_attribute(self.baseSchema, attrPath=path, pathSep=self.refPathSep, defaultValue=None)
        except:
            traceback.print_exc()
            print("It was not possible to get schema reference")
            return None

if __name__ == '__main__':
    """Test of the parsing functionality of this class"""
    testRequest = op.read_json_file("./test/schemaRequest.json")
    semanticId = op.get_attribute(testRequest, "semanticId")
    schema = op.get_attribute(testRequest, "schema")

    if not semanticId:
        HttpUtils.get_error_response(message="No semantic id specified", status=403)
    if not schema:
        HttpUtils.get_error_response(message="No schema specified", status=403)

    parser = sammSchemaParser(semanticId=semanticId)
    newProperty = parser.schema_to_jsonld(schema=schema)
    op.to_json_file({"@context":newProperty}, "./export/property.json", "w", 5)
"""     parser.baseSchema = schema
    testObj = {
                "description": "Properties connected with the handling of the product.",
                "$ref": "#/components/schemas/urn_samm_io.catenax.generic.digital_product_passport_5.0.0_HandlingCharacteristic"
            }
    sub_schema = parser.get_schema_ref(obj=testObj)
    props = op.get_attribute(sourceObject=sub_schema, attrPath=parser.propertiesKey)
    key = "content"
    property = props[key]
    print(property)
    newProperty = dict() 

    # If the property has a reference
    if parser.refKey in property:
        oldProperty = parser.get_schema_ref(obj=property)
    
    if not oldProperty:
        raise Exception("It was not possible to get the value of the property!")

    if not "type" in oldProperty:
        print("Error: No type property")
    
    nodeType = op.get_attribute(oldProperty, "type")
    newProperty["@type"] = f"schema:{nodeType}"
    
    newProperty["@id"] = f"aspect:{key}"

    if "description" in property:
        newProperty["@definition"] = op.get_attribute(property, "description")
    elif "description" in oldProperty:
        newProperty["@definition"] = op.get_attribute(oldProperty, "description")
    
    if nodeType == "object":
        print("its object")
        newProperty["id"] = "@id"
        props = op.get_attribute(sourceObject=oldProperty, attrPath=parser.propertiesKey)
        print(props)
        if not props:
            raise Exception("It was not possible to generated the json-ld because properties of object were null!")
        jsonLd = dict()
        
        jsonLd["@version"] = 1.1
        jsonLd["id"] = "@id"
        jsonLd["type"] = "@type"

        for t_key, t_value in props.items():
            print(f"{t_key} = {t_value}")
            t_newProperty = dict() 
            t_oldProperty = t_value
            # If the property has a reference
            if parser.refKey in t_value:
                t_oldProperty = parser.get_schema_ref(obj=t_value)
            
            if not t_oldProperty:
                raise Exception("It was not possible to get the value of the property!")

            if not "type" in t_oldProperty:
                print("Error: No type property")
            
            t_nodeType = op.get_attribute(t_oldProperty, "type")
            t_newProperty["@type"] = f"schema:{t_nodeType}"
            
            t_newProperty["@id"] = f"aspect:{t_key}"

            if "description" in t_value:
                t_newProperty["@definition"] = op.get_attribute(t_value, "description")
            elif "description" in t_oldProperty:
                t_newProperty["@definition"] = op.get_attribute(t_oldProperty, "description")
            
            if t_nodeType == "object":
                print("its object")
                t_newProperty["id"] = "@id"
                t_newProps = op.get_attribute(sourceObject=t_oldProperty, attrPath=parser.propertiesKey)
                print(props)
                if not t_newProps:
                    raise Exception("It was not possible to generated the json-ld because properties of object were null!")
                t_newJsonLd = dict()
                
                t_newJsonLd["@version"] = 1.1
                t_newJsonLd["id"] = "@id"
                t_newJsonLd["type"] = "@type"

                for t_t_key, t_t_value in t_newProps.items():
                    print(f"{t_t_key} = {t_t_value}")
                    t_newJsonLd[t_t_key] = {}
                
                print(t_newJsonLd)
                t_newProperty["@context"] = t_newJsonLd
                #context = parser.generate_properties(properties=props, jsonLd=dict())
                #if context:
                #    newProperty["@context"] = context

            if t_nodeType == "array":
                print("its array")
                t_newProperty["@container"] = "@list"
                t_item = op.get_attribute(sourceObject=t_oldProperty, attrPath=parser.itemKey)
                print(t_item)
                if not t_item:
                    raise Exception("It was not possible to generated the json-ld because properties of object were null!")
                t_context = parser.generate_item(item=t_item, itemKey=t_key)
                if t_context:
                    t_newProperty["@context"] = t_context
                else:
                    print("Item is empty!")
                
            jsonLd[t_key] = t_newProperty 
        
        print(jsonLd)
        newProperty["@context"] = jsonLd
        #context = parser.generate_properties(properties=props, jsonLd=dict())
        #if context:
        #    newProperty["@context"] = context

    if nodeType == "array":
        print("its array")
        newProperty["@container"] = "@list"
        item = op.get_attribute(sourceObject=oldProperty, attrPath=parser.itemKey)
        print(item)
        if not item:
            raise Exception("It was not possible to generated the json-ld because properties of object were null!")
        #context = parser.generate_item(item=item, itemKey=key, jsonLd=newProperty)
        #if context:
        #    newProperty["@context"] = context """