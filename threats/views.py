import datetime
import socket
import uuid

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.reverse import reverse
from rest_framework import status
from threat import *
from serializers import *
from models import Traffic


class TrafficMixin(object):
    def dispatch(self, request, *args, **kwargs):
        alienvault_id = uuid.uuid4().hex[:12]

        if not request.COOKIES.get('AlienvaultID'):
            alienvault_id = uuid.uuid4().hex[:12]
        else:
            alienvault_id = request.COOKIES.get('AlienvaultID')

        # Create the record for statistics
        new_traffic = Traffic(
            address = request.META.get('REMOTE_ADDR'),
            timestamp = str(time.time()),
            endpoint = request.path,
            alienvault_id = alienvault_id
        )
        
        new_traffic.save()

        return super(TrafficMixin, self).dispatch(request, alienvault_id=alienvault_id, *args, **kwargs)

def set_cookie(request, response, alienvault_id):
    if not request.COOKIES.get('AlienvaultID'):
        response.set_cookie(
            "AlienvaultID",
            alienvault_id,
            expires=datetime.datetime.strftime(
                datetime.datetime.utcnow() + datetime.timedelta(days=365), 
                "%a, %d-%b-%Y %H:%M:%S GMT"
            )
        )


class APIRoot(Traffic, APIView):
    def get(self, request):
        return Response({
            'IP Details': reverse('threat_details', request=request),
        })

		
class IPDetailsView(Traffic, APIView):
    def get(self, request, *args, **kw):
        ip = kw.get('ip')

        try:
            socket.inet_aton(ip)
        except socket.error:
            return Response("IP Address is not valid", status=status.HTTP_400_BAD_REQUEST)
		
        details_request = IPDetails(ip, *args, **kw)
        
        result = DetailsSerializer(details_request)

        response = Response(result.data, status=status.HTTP_200_OK)

        set_cookie(request, response, kw.get('alienvault_id', uuid.uuid4().hex[:12]))

        return response

		
class TrafficView(TrafficMixin, APIView):
    def get(self, request, *args, **kw):
        traffic = Traffic.objects.all()

        traffic_response = []
        used_ids = []

        for users in traffic.values():
            if users["alienvault_id"] in used_ids:
                continue

            user = {
                "alienvaultid": users['alienvault_id'],
                "visits": [
                    {
                        "address": visit['address'],
                        "timestamp": visit['timestamp'],
                        "endpoint": visit['endpoint']
                    } for visit in traffic.values() if visit['alienvault_id'] == users['alienvault_id']
                ]
            }

            traffic_response.append(user)
            used_ids.append(users['alienvault_id'])

        response = Response(traffic_response, status=status.HTTP_200_OK)
        set_cookie(request, response, kw.get('alienvault_id', uuid.uuid4().hex[:12]))
        return response
