from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.response import Response
from vuln.models import vulnerabilities
from .serializer import vulnerabilitySerealizer, UserSerealizer
from django.contrib.auth.models import User
from rest_framework.authtoken.models import Token
from django.shortcuts import get_object_or_404
from rest_framework.decorators import authentication_classes, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import TokenAuthentication
from .funciones import consumir_api, modelar_data_api, filter_vulnerability_severity, excluir_fix


#Registro de usuario
@api_view(['POST'])   
def register(request):
    serealizer = UserSerealizer(data=request.data)
    if serealizer.is_valid():
        serealizer.save()
        
        user = User.objects.get(username=serealizer.data['username'])
        user.set_password(serealizer.data['password'])
        user.save()
        token = Token.objects.create(user=user)
        return Response({'token': token.key, 'user': serealizer.data}, status=status.HTTP_200_OK )
    
    return Response(serealizer.errors, status=status.HTTP_400_BAD_REQUEST)


#Loguin de usuario
@api_view(['POST'])   
def loguin(request):
    
    user = get_object_or_404(User, username=request.data['username']) 
    
    if not user.check_password(request.data['password']):
        return Response({'error': "Invalid password"}, status=status.HTTP_400_BAD_REQUEST)
    
    token, created = Token.objects.get_or_create(user=user)
    serealizer = UserSerealizer(instance=user)
    
    return Response({'token': token.key, 'user': serealizer.data}, status=status.HTTP_200_OK)

 
#Profile de usuario
@api_view(['POST'])   
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def profile(request):
    
    print(request.user)
    
    
    return Response({'you are authenticated with': request.user.username}, status=status.HTTP_200_OK)
 
       
       

#GET que devuelve el listado total de las vulnerabilidades  
@api_view(['GET'])  
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated]) 
def vuln_api_view(request):
    try:
        if request.method == 'GET':
            info_api = consumir_api()
            data_modelada = modelar_data_api(info_api)
            return Response(data_modelada, status=status.HTTP_200_OK)
    except:
         return Response({'the request has failed in vuln_api_view'}, status=status.HTTP_400_BAD_REQUEST)


#Endpoint POST que reciba las vulns fixeadas.
@api_view(['GET', 'POST'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def vuln_fix_view(request):
    if request.method == 'GET':
        try:
            vulnerabiliti = vulnerabilities.objects.all()
            vuln_serializer = vulnerabilitySerealizer(vulnerabiliti, many=True)
            return Response(vuln_serializer.data, status=status.HTTP_200_OK)
        except:
            return Response({'the request has failed in vuln_fix_view GET'}, status=status.HTTP_400_BAD_REQUEST)
    
    elif request.method == 'POST':
        try:
            vuln_serializer = vulnerabilitySerealizer(data=request.data)
            if vuln_serializer.is_valid():
                vuln_serializer.save()
                return Response(vuln_serializer.data, status=status.HTTP_200_OK) 
            return Response(vuln_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except:
            return Response({'the request has failed in vuln_fix_view POST'}, status=status.HTTP_400_BAD_REQUEST)


        
#Endpoint GET que devuelva el listado de vulnerabilidades exceptuando las fixeadas
@api_view(['GET'])   
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def vuln_no_fix(request):
    try:
        if request.method == 'GET':
            info_api = consumir_api()
            vuln_nofix = excluir_fix(info_api)
            return Response(vuln_nofix, status=status.HTTP_200_OK)
    except:
        return Response({'the request has failed'}, status=status.HTTP_400_BAD_REQUEST)

     


#Endpoint GET que permita obtener información sumarizada de vulnerabilidades por severidad.
@api_view(['GET'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def vuln_for_severity(request, severity):
    try:
        if request.method == 'GET':
            info_api = filter_vulnerability_severity(severity)
            data_modelada = excluir_fix(info_api)
            return Response(data_modelada, status=status.HTTP_200_OK)
    except:
        return Response({'the request has failed'}, status=status.HTTP_400_BAD_REQUEST)

            
        

    
    