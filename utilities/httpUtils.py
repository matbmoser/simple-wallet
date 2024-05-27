import requests
from flask import jsonify, Response, make_response
class HttpUtils:

    # do post request without session
    def do_get(url,verify=False,headers=None,timeout=None,params=None,allow_redirects=False):
        return requests.get(url=url,verify=verify,
                            timeout=timeout,headers=headers,
                            params=params,allow_redirects=allow_redirects)
    
    # do get request with session
    def do_get(url,session=None,verify=False,headers=None,timeout=None, params=None,allow_redirects=False):
        if session is None:
            session = requests.Session()
        return session.get(url=url,verify=verify,
                           timeout=timeout,headers=headers,
                           params=params,allow_redirects=allow_redirects)
    
    # do post request without session
    def do_post(url,data=None,verify=False,headers=None,timeout=None,json=None,allow_redirects=False):
        return requests.post(url=url,verify=verify,
                             timeout=timeout,headers=headers,
                             data=data,json=json,
                             allow_redirects=allow_redirects)
    
    # do post request with session
    def do_post(url,session=None,data=None,verify=False,headers=None,timeout=None,json=None,allow_redirects=False):
        if session is None:
            session = requests.Session()
        return session.post(url=url,verify=verify,
                            timeout=timeout,headers=headers,
                            data=data,json=json,
                            allow_redirects=allow_redirects)
        # do post request with session
    @staticmethod
    def response(data, status=200, content_type='application/json'):
        response = make_response(data, status)
        response.headers["Content-Type"] = content_type
        return response
    
    # Generates a error response with message
    @staticmethod
    def get_error_response(status=500,message="It was not possible to process/execute this request!"):
        return HttpUtils.response({
            "message": message,
            "status": status
        }, status)
    
    @staticmethod
    def get_body(request):
        return request.get_json()
   