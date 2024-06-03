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
    def __init__(self, semanticId="urn:samm:io.catenax.generic.digital_product_passport:5.0.0#"):
        self.baseSchema = dict()
        self.rootRef = "#"
        self.refKey = "$ref"
        self.pathSep = "/"
        self.propertiesKey = "properties"
        self.itemKey = "items"
        self.schemaPrefix = "schema"
        self.aspectPrefix = "aspect"
        self.contextPrefix = "@context"
        self.complexTypes = ["object", "array"]
        self.initialJsonLd = {
                self.schemaPrefix: "https://schema.org/",
                self.aspectPrefix: semanticId,
        }
        self.contextTemplate = {
            "@version": 1.1,
            "id": "@id",
            "type": "@type"
        }
    
    def schema_to_jsonld(self, schema):
        self.baseSchema = copy.deepcopy(schema)
        jsonLdContext = self.expand_node(node=schema, parent=self.initialJsonLd) 

        if not jsonLdContext:
            raise Exception("It was not possible to generated the json-ld!")

        return jsonLdContext
    

    """ schema -> @context
     
      schema 

        "array" -> "items"
        "object" -> "properties"
        "description"
        "type"
      
      @context
        
      
        node["type"] == "array"
        "array of objects" -> 
            @container: "@list" (or "@set")
            @id -> object id  
            @context -> 
                @version: 1.1
                id: @id
                type: @type
                "prop1" ->
                "prop2" ->  
        "array of strings/numbers" -> 

        node["type"] == "object"
        "object" ->
            @id -> object id | "aspect:{node key}"        
            @context -> {parent propeties}
                @version: 1.1
                id: @id
                type: @type
                "prop1" ->  | child properties key
                "prop2" ->  | child properties key
        
                
        node["type"] == "string":
            @id -> object id | "aspect:{node key}"
            @type -> {node type}
            @definition -> node description

          """
    def expand_node(self, ref):
        ## Ref must not be None
        if(ref is None):
            return None

        ## Get expanded node
        expandedNode = self.get_schema_ref(ref=ref)
        if(expandedNode is None):
            return None

        return self.create_node(property=expandedNode)



    """
    
    upper schema -> return context
    
    """
    def create_node(self, property):
        ## Schema must be not none and type must be in the schema
        if (property is None) or (not "type" in property):
            return None
        
        ## Start by creating a simple node
        node = self.create_simple_node(property=property)

        ## If is not possible to create the simple node it is not possible to create any node
        if(node is None):
            return None

        propertyType = property["type"]

        if propertyType == "object":
            return self.create_object_node(property=property, node=node)
        
        if propertyType == "array":
            return self.create_array_node(property=property, node=node)
        
        return self.create_value_node(property=property, node=node)

    def create_value_node(self, property, node):
        
        ## If type exists add definition to the node
        if not ("type" in property):
            return None
        
        node["@type"] = self.schemaPrefix+":"+property["type"]
        return node
    
    def create_object_node(self, property, node):
        
        ## If object has not the properties key
        if not (self.propertiesKey in property):
            return None
        
        properties = property[self.propertiesKey]

        node[self.contextPrefix] = self.create_properties_context(properties=properties)
        return node

    def create_array_node(self, property, node):
        
        ## If array node has not the item key
        if not (self.itemKey in property):
            return None
        
        item = property[self.itemKey]
        node["@container"] = "@list" 

        ## If list is with different types of data, dont specify a type
        if(isinstance(item, list)):
            return node

        node[self.contextPrefix] = self.create_item_context(item=item)
        return node


    
    """
        adds context to node with properties
        node = {
            @id -> asdsad
        }
        "OBJECT NODE" 

        HAS PROPERTIES
    """
    def create_properties_context(self, properties):
        ## If no key is provided or node is empty
        if(properties is None):
            return None
        
        ## If no key is found
        if(not isinstance(properties, dict)):
            return None
        
        ## If no keys are provided in the properties
        if(len(properties.keys())  == 0):
            return None
        
        ## Create new context dict from template
        newContext = copy.deepcopy(self.contextTemplate)
        oldProperties = copy.deepcopy(properties)

        ## Fill the node context with the properties
        for propKey, prop in oldProperties.items():
            newContext[propKey] = self.create_node_property(key=propKey, node=prop)

        ## Add context properties to the node context
        return newContext

    def create_item_context(self, item):
        ## If no key is provided or node is empty
        if(item is None):
            return None
        
        if not (self.refKey in item):
            return self.create_value_node(property=item)
        ref = item[self.refKey]
        nodeItem = self.expand_node(ref=ref)
        
        ## If was not possible to get the reference return None
        if nodeItem is None:
            return None

        ## Overite the existing description of ref item
        if "description" in item:
            nodeItem["@definition"] = item["description"]

        return nodeItem
        
    def create_node_property(self, key, node):
        ## If no key is provided or node is empty
        if(key is None) or (node is None):
            return None

        ## Ref property must exist in a property inside properties
        if not (self.refKey in node):
            return None

        ## Get reference from the base schema
        ref = node[self.refKey]
        nodeProperty = self.expand_node(ref=ref)

        ## If was not possible to get the reference return None
        if nodeProperty is None:
            return None

        ## Overite the existing description of ref property
        if "description" in node:
            nodeProperty["@definition"] = node["description"]

        return nodeProperty


    def create_simple_node(self, property, key=None):
        """
        Creates a simple node with key and object from a schema property
        Receives:
            key: :str: attribute key
            node: :dict: contains the node object with or without description and type
        Returns:
            response: :dict: json ld simple node with the information of the node object
        """
        ## If no key is provided or node is empty
        if (property is None):
            return None
        
        ## Create new json ld simple node
        newNode = dict()

        ## If the key is not none create a new node
        if not (key is None):
            newNode["@id"] = self.schemaPrefix+":"+key
    
        ## If description exists add definition to the node
        if "description" in property:
            newNode["@definition"] = property["description"]
        
        return newNode
    
            

    def generate_properties(self, schema, context=dict()):
        
        # All properties will be collected here
        properties = op.get_attribute(sourceObject=schema, attrPath=self.propertiesKey)
        if not properties:
            raise Exception("It was not possible to get the properties attribute!")
        if not properties or len(properties.keys()) == 0:
            return None
        
        context["@version"] = 1.1
        context["id"] = "@id"
        context["type"] = "@type"

        newProperty = dict() 

        # If the property has a reference
        if self.refKey in value:
            newSchema = self.get_schema_ref(obj=value)
        
        if not newSchema:
            raise Exception("It was not possible to get the value of the property!")

        if not "type" in newSchema:
            raise Exception("It was not possible to get the value of the property by type!")
        
        nodeType = op.get_attribute(newSchema, "type")
        newProperty["@type"] = f"schema:{nodeType}"
        newProperty["@id"] = f"aspect:{key}"

        if "description" in value:
            newProperty["@definition"] = op.get_attribute(value, "description")
        elif "description" in newSchema:
            newProperty["@definition"] = op.get_attribute(newSchema, "description")
        
        complexNodeTypes = ["object", "array"]

        ## If is string
        if not nodeType in complexNodeTypes:
            context[key] = newProperty
            return 


        if nodeType == "object":
            ## If is object
            newProperty["id"] = "@id"
            newProperty["@context"] = self.generate_properties(schema=newSchema, context=newProperty)

        if nodeType == "array":
            newProperty["@container"] = "@list"
            item = op.get_attribute(sourceObject=newSchema, attrPath=self.itemKey)
            if not item:
                raise Exception("It was not possible to generated the json-ld because properties of object were null!")

            newItem = dict() 

            if "type" in item:
                newItem["@type"] = f"schema:{op.get_attribute(item, "type")}"
                newItem["@id"] = f"aspect:{key}"
                return

            if not self.refKey in item:
                return

            newItem["id"] = "@id"

            reference = self.get_schema_ref(obj=item)
            if not reference:
                raise Exception("The reference key was not found!")
            
            newItem["@version"] = 1.1
            
            newProperty["@context"] = self.generate_properties(schema=reference, context=newItem)

            context[key] = newProperty
        
        return context
    
    def generate_property(self, key, property, context):
        
        newProperty = dict() 
        schema = property
        # If the property has a reference
        if self.refKey in property:
            schema = self.get_schema_ref(obj=property)
        
        if not schema:
            raise Exception("It was not possible to get the value of the property!")

        if not "type" in schema:
            raise Exception("It was not possible to get the value of the property by type!")
        
        nodeType = op.get_attribute(schema, "type")
        newProperty["@type"] = f"schema:{nodeType}"
        newProperty["@id"] = f"aspect:{key}"

        if "description" in property:
            newProperty["@definition"] = op.get_attribute(property, "description")
        elif "description" in schema:
            newProperty["@definition"] = op.get_attribute(schema, "description")
        
        complexNodeTypes = ["object", "array"]

        ## If is string
        if not nodeType in complexNodeTypes:
            context[key] = newProperty
            return newProperty


        if nodeType == "object":
            ## If is object
            newProperty["id"] = "@id"
            self.generate_properties(schema=schema, context=newProperty)

        if nodeType == "array":
            newProperty["@container"] = "@list"
            item = op.get_attribute(sourceObject=schema, attrPath=self.itemKey)
            if not item:
                raise Exception("It was not possible to generated the json-ld because properties of object were null!")

            newItem = dict() 

            if "type" in item:
                newItem["@type"] = f"schema:{op.get_attribute(item, "type")}"
                newItem["@id"] = f"aspect:{key}"
                return newItem

            if not self.refKey in item:
                return None

            newItem["id"] = "@id"

            reference = self.get_schema_ref(obj=item)
            if not reference:
                raise Exception("The reference key was not found!")
            
            newItem["@version"] = 1.1
            
            self.generate_properties(schema=reference, context=newItem)

        context[key] = newProperty
        return newProperty
        

    def generate_item(self, schema, itemKey, context):
        
        item = op.get_attribute(sourceObject=schema, attrPath=self.itemKey)
        if not item:
            raise Exception("It was not possible to generated the json-ld because properties of object were null!")

        newItem = dict() 

        if "type" in item:
            newItem["@type"] = f"schema:{op.get_attribute(item, "type")}"
            newItem["@id"] = f"aspect:{itemKey}"
            return newItem

        if not self.refKey in item:
            return None

        newItem["id"] = "@id"

        reference = self.get_schema_ref(obj=item)
        if not reference:
            raise Exception("The reference key was not found!")
        
        newItem["@version"] = 1.1
        
        self.generate_properties(schema=reference, context=newItem)

        return newItem
    

    def get_schema_ref(self, ref):
        path = ref.removeprefix("#/")        
        return op.get_attribute(self.baseSchema, attrPath=path, pathSep=self.pathSep, defaultValue=None)

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