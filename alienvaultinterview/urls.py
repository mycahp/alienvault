from django.conf.urls import url, include
from rest_framework import routers
from threats.views import IPDetailsView, APIRoot, TrafficView

urlpatterns = [
    url(r'^$', APIRoot.as_view(), name='api_root'),
	url(r'api/threat/ip/?(?P<ip>[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})$', IPDetailsView.as_view(), name='threat_details'),
    url(r'api/traffic/$', TrafficView.as_view(), name="traffic_details")
]