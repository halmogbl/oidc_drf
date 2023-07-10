from django.http import JsonResponse
from django.contrib import auth
from rest_framework.permissions import AllowAny
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from urllib.parse import urlencode
from django.utils.crypto import get_random_string
from oidc_drf.utils import import_from_settings
import requests


class OIDCGenerateAuthenticationUrlView(APIView):
    permission_classes = [AllowAny]    
    def login_failure(self,error_message,status):
        return Response({"detail":error_message}, status=status)
    
    def get(self, request):
        state = get_random_string(import_from_settings("OIDC_STATE_SIZE", 32))
        auth_url = import_from_settings("OIDC_OP_AUTHORIZATION_ENDPOINT")

        params ={
            "response_type":  'code',
            "client_id":  import_from_settings("OIDC_RP_CLIENT_ID"),
            "redirect_uri":  import_from_settings("OIDC_AUTHENTICATION_SSO_CALLBACK_URL"),
            "scope":  import_from_settings("OIDC_RP_SCOPES"),
            "state":  state,
        }
        
        if import_from_settings("OIDC_USE_NONCE", True):
            nonce = request.GET.get('nonce',None)
            if nonce == None:
                return self.login_failure("missing nonce",status.HTTP_400_BAD_REQUEST)
            params.update({"nonce": nonce})

        if import_from_settings("OIDC_USE_PKCE", True):            
            code_challenge = request.GET.get('code_challenge',None)
            code_challenge_method = request.GET.get('code_challenge_method',None)
            if code_challenge == None:
                return self.login_failure("missing code_challenge",status.HTTP_400_BAD_REQUEST)
            if code_challenge_method == None:
                return self.login_failure("missing code_challenge_method",status.HTTP_400_BAD_REQUEST)
            params.update(
                {
                    "code_challenge": code_challenge,
                    "code_challenge_method": code_challenge_method,
                })
            
        query = urlencode(params)
        redirect_url = "{url}?{query}".format(url=auth_url, query=query)

        return Response({
            "redirect_url":redirect_url
            } )

class OIDCAuthenticationCallbackView(APIView):
    """OIDC client authentication callback HTTP endpoint"""
    permission_classes = [AllowAny]    

    def login_failure(self,error_message,status):
        return Response({"detail":error_message}, status=status)

    def login_success(self):   
        try:     
            oidc_access_token = self.request.session["oidc_access_token"]
            oidc_refresh_token = self.request.session["oidc_refresh_token"]
            
            data = {
                'access': str(oidc_access_token),
                'refresh': str(oidc_refresh_token),
            } 
            
            del self.request.session["oidc_access_token"]
            del self.request.session["oidc_refresh_token"]
            self.request.session.save()

            
            return JsonResponse(data)
    
        except:
            return self.login_failure("Login failed",status.HTTP_401_UNAUTHORIZED)

    def post(self, request):
        """Callback handler for OIDC authorization code flow"""
        data = request.data
        
        if import_from_settings("OIDC_USE_PKCE", True):
            code_verifier = data.get("code_verifier",None)
            if code_verifier == None:
                return self.login_failure("missing code_verifier",status.HTTP_400_BAD_REQUEST)
            
        if import_from_settings("OIDC_USE_NONCE", True):
            nonce = data.get("nonce",None)
            if nonce == None:
                return self.login_failure("missing nonce",status.HTTP_400_BAD_REQUEST)
            
        if "error" in request.GET:
            return self.login_failure(request.GET.get("error_description"),status.HTTP_400_BAD_REQUEST)
        
        elif "code" in request.GET and "state" in request.GET:            
            kwargs = {
                "request": request,
                "nonce": data.get("nonce",None),
                "code_verifier": data.get("code_verifier",None),
            }
            self.user = auth.authenticate(**kwargs)
                        
            if self.user:
                return self.login_success()
        
        return self.login_failure("Login failed",status.HTTP_401_UNAUTHORIZED)

class OIDCLogoutView(APIView):
    permission_classes = [AllowAny]    
    def login_failure(self,error_message,status):
        return Response({"detail":error_message}, status=status)
    
    def post(self, request):     
        client_id = import_from_settings("OIDC_RP_CLIENT_ID", "")
        client_secret = import_from_settings("OIDC_RP_CLIENT_SECRET", "")
        refresh = request.data.get('refresh', None)
        
        if refresh == None:
            return self.login_failure("missing refresh field",status.HTTP_400_BAD_REQUEST)
        else:

            logout_endpoint = import_from_settings("OIDC_OP_LOGOUT_ENDPOINT", "")            
            headers = {
                'Content-Type': 'application/x-www-form-urlencoded',
            }

            data = {
                'client_id': client_id,
                'client_secret': client_secret,
                'refresh_token': refresh,
            }
            
            response = requests.post(logout_endpoint, data=data, headers=headers)
            
            if response.status_code == 204:
                return JsonResponse({'message': 'Logout OIDC Successful'}, status=status.HTTP_200_OK)
            else:
                error_message = response.json().get('error', 'Logout Request failed with status code: {}'.format(response.status_code))
                error_data = {
                    'error': error_message
                }
                return JsonResponse(error_data, status=response.status_code)

class OIDCRefreshTokenView(APIView):
    permission_classes = [AllowAny]    
    def login_failure(self,error_message,status):
        return Response({"detail":error_message}, status=status)
    
    def post(self, request):     
        url = import_from_settings("OIDC_OP_TOKEN_ENDPOINT", "")
        refresh_token = request.data.get("refresh",None)
        code_verifier = request.data.get("code_verifier",None)
        client_secret = import_from_settings("OIDC_RP_CLIENT_SECRET", "")
        client_id = import_from_settings("OIDC_RP_CLIENT_ID", "")

        if import_from_settings("OIDC_USE_PKCE", True) and code_verifier == None:
            return self.login_failure("missing code_verifier",status.HTTP_400_BAD_REQUEST)
            
        if refresh_token == None:
            return self.login_failure("missing code_verifier",status.HTTP_400_BAD_REQUEST)

        data = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": client_id,
            "code_verifier": code_verifier,
            "client_secret": client_secret
        }
        
        headers = {
            "Content-Type": "application/x-www-form-urlencoded"
        }
        
        try:
            response = requests.post(url, data=urlencode(data), headers=headers)
            json_data = response.json()
            
            if response.status_code != 200:
                error_message = json_data.get('error', 'Request failed with status code: {}'.format(response.status_code))
                error_data = {
                    'error': error_message
                }
                return JsonResponse(error_data, status=response.status_code)
            
            oidc_access_token = json_data.get("access_token")
            oidc_refresh_token = json_data.get("refresh_token")
            
            data = {
                'access': str(oidc_access_token),
                'refresh': str(oidc_refresh_token),
            }       
    
            return JsonResponse(data)
        except requests.exceptions.RequestException as e:
            # Handle any request exceptions here
            error_message = str(e)
            error_data = {
                'error': error_message
            }
            return JsonResponse(error_data, status=response.status_code)


    

