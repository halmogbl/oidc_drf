from django.http import JsonResponse
from django.contrib import auth
from rest_framework.permissions import AllowAny,IsAuthenticated
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from urllib.parse import urlencode
from django.utils.crypto import get_random_string
from oidc_drf.utils import import_from_settings
import requests


from  oidc_drf.utils import generate_code_challenge

class OIDCGenerateAuthenticationUrlView(APIView):
    permission_classes = [AllowAny]    
    def get(self, request):

        state = get_random_string(import_from_settings("OIDC_STATE_SIZE", 32))
        auth_url = import_from_settings("OIDC_OP_AUTHORIZATION_ENDPOINT")
        # oidc_states = {}

        params ={
            "response_type":  'code',
            "client_id":  import_from_settings("OIDC_RP_CLIENT_ID"),
            "redirect_uri":  import_from_settings("OIDC_AUTHENTICATION_SSO_CALLBACK_URL"),
            "scope":  import_from_settings("OIDC_RP_SCOPES"),
            "state":  state,
        }
        

        
        if import_from_settings("OIDC_USE_NONCE", True):
            # nonce = get_random_string(import_from_settings("OIDC_NONCE_SIZE", 32))
            nonce = request.GET.get('nonce')
            params.update({"nonce": nonce})
            # oidc_states.update({"nonce":nonce})



        if import_from_settings("OIDC_USE_PKCE", True):
            # code_verifier_length = import_from_settings("OIDC_PKCE_CODE_VERIFIER_SIZE", 64)
            # Check that code_verifier_length is between the min and max length
            # defined in https://datatracker.ietf.org/doc/html/rfc7636#section-4.1
            # if not (43 <= code_verifier_length <= 128):
            #     raise ValueError("code_verifier_length must be between 43 and 128")

            # Generate code_verifier and code_challenge pair
            # code_verifier = get_random_string(code_verifier_length)


            # oidc_states.update({"code_verifier":code_verifier})
            # code_challenge_method = import_from_settings(
            #     "OIDC_PKCE_CODE_CHALLENGE_METHOD", "S256"
            # )
            # code_challenge = generate_code_challenge(
            #     code_verifier, code_challenge_method
            # )

            # Append code_challenge to authentication request parameters
            
            code_challenge = request.GET.get('code_challenge')
            code_challenge_method = request.GET.get('code_challenge_method')
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

    def login_failure(self):
        return Response({"detail":"Login failed"}, status=status.HTTP_401_UNAUTHORIZED)


    def login_success(self):   
        try:     
            oidc_access_token = self.request.session["oidc_access_token"]
            oidc_id_token = self.request.session["oidc_id_token"]
            oidc_refresh_token = self.request.session["oidc_refresh_token"]
            
            data = {
                'access': str(oidc_access_token),
                'refresh': str(oidc_refresh_token),
                'oidc_id_token': str(oidc_id_token),
            } 
            
            del self.request.session["oidc_access_token"]
            del self.request.session["oidc_id_token"]
            del self.request.session["oidc_refresh_token"]
            self.request.session.save()

            
            return JsonResponse(data)
    
        except:
            return self.login_failure()


    def post(self, request):
        """Callback handler for OIDC authorization code flow"""

        if "code" in request.GET and "state" in request.GET:

            data = request.data
            
            kwargs = {
                "request": request,
                "nonce": data.get("nonce",""),
                "code_verifier": data.get("code_verifier",""),
            }

            self.user = auth.authenticate(**kwargs)
            
            if self.user and self.user.is_active:
                return self.login_success()
        
        return self.login_failure()

class OIDCLogoutView(APIView):
    permission_classes = [AllowAny]    

    def post(self, request):     
        oidc_id_token = request.data.get('oidc_id_token', '')
        if oidc_id_token:

            logout_endpoint = import_from_settings("OIDC_OP_LOGOUT_ENDPOINT", "")
            post_logout_redirect_uri = import_from_settings("OIDC_LOGOUT_REDIRECT_URL", "http://localhost:3000")
            
            headers = {
                'Content-Type': 'application/x-www-form-urlencoded',
            }

            data = {
                'post_logout_redirect_uri': post_logout_redirect_uri,
                'id_token_hint': oidc_id_token,
            }
            response = requests.post(logout_endpoint, data=data, headers=headers)
            
            if response.status_code != 200:
                error_message = response.json().get('error', 'Logout Request failed with status code: {}'.format(response.status_code))
                error_data = {
                    'error': error_message
                }
                return JsonResponse(error_data, status=response.status_code)

        
            if response.status_code == 204 or response.status_code == 200:
                return JsonResponse({'message': 'Logout OIDC successful'}, status=response.status_code)
            
        return Response({"error":"user has not id token !!"}, status=status.HTTP_400_BAD_REQUEST)    

class OIDCRefreshTokenView(APIView):
    permission_classes = [AllowAny]    

    def post(self, request):     
        url = import_from_settings("OIDC_OP_TOKEN_ENDPOINT", "")
        refresh_token = request.data.get("refresh",'')
        code_verifier = request.data.get("code_verifier",'')
        client_secret = import_from_settings("OIDC_RP_CLIENT_SECRET", "")
        client_id = import_from_settings("OIDC_RP_CLIENT_ID", "")

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
            oidc_id_token = json_data.get("id_token")
            oidc_refresh_token = json_data.get("refresh_token")
            
            data = {
                'access': str(oidc_access_token),
                'refresh': str(oidc_refresh_token),
                'oidc_id_token': str(oidc_id_token),
            }       
    
            return JsonResponse(data)
        except requests.exceptions.RequestException as e:
            # Handle any request exceptions here
            error_message = str(e)
            error_data = {
                'error': error_message
            }
            return JsonResponse(error_data, status=response.status_code)


    

