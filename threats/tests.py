# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from threat import IPDetails
from serializers import DetailsSerializer

from django.test import TestCase
from rest_framework.test import RequestsClient, APITestCase
from rest_framework.reverse import reverse
from rest_framework import status


class IPDetailsTest(TestCase):
    def test_no_rep_resposne(self):
        details_request = IPDetails("136.62.143.0")
        result = DetailsSerializer(details_request)

        self.assertEqual(
            result.data,
            {
                "address": "136.62.143.0",
                "is_tracked": False,
                "is_error": False,
                "id": "",
                "reputation_val": 0,
                "first_activity": None,
                "last_activity": None,
                "activities": [],
                "activity_types": [],
                "is_valid": True
            }
        )

    def test_rep_response(self):
        details_request = IPDetails("69.43.161.174")
        result = DetailsSerializer(details_request)

        self.assertEqual(
            result.data,
            {  
            'first_activity':1319315215,
            'activities':[  
                {  
                    'first_date':1319315215,
                    'late_date':1322894309,
                    'activity_type':u'Malicious Host'
                },
                {  
                    'first_date':1320136886,
                    'late_date':1322929165,
                    'activity_type':u'Malicious Host'
                },
                {  
                    'first_date':1323519620,
                    'late_date':1323519620,
                    'activity_type':u'Malicious Host'
                },
                {  
                    'first_date':1323562907,
                    'late_date':1323562907,
                    'activity_type':u'Malicious Host'
                },
                {  
                    'first_date':1323567736,
                    'late_date':1323567736,
                    'activity_type':u'Malicious Host'
                },
                {  
                    'first_date':1323765787,
                    'late_date':1323765787,
                    'activity_type':u'Malicious Host'
                },
                {  
                    'first_date':1329023299,
                    'late_date':1329432953,
                    'activity_type':u'Malware Domain'
                },
                {  
                    'first_date':1332267599,
                    'late_date':1333207073,
                    'activity_type':u'Malware Domain'
                },
                {  
                    'first_date':1340890642,
                    'late_date':1342623359,
                    'activity_type':u'C&C'
                },
                {  
                    'first_date':1340881192,
                    'late_date':1343235622,
                    'activity_type':u'Malware Domain'
                },
                {  
                    'first_date':1340366753,
                    'late_date':1341737916,
                    'activity_type':u'Spamming'
                },
                {  
                    'first_date':1340366753,
                    'late_date':1341737916,
                    'activity_type':u'Spamming'
                },
                {  
                    'first_date':1340366753,
                    'late_date':1341737916,
                    'activity_type':u'Spamming'
                },
                {  
                    'first_date':1340366753,
                    'late_date':1341737916,
                    'activity_type':u'Spamming'
                },
                {  
                    'first_date':1340366753,
                    'late_date':1341737916,
                    'activity_type':u'Spamming'
                },
                {  
                    'first_date':1340366753,
                    'late_date':1341737916,
                    'activity_type':u'Spamming'
                },
                {  
                    'first_date':1340366753,
                    'late_date':1341737916,
                    'activity_type':u'Spamming'
                },
                {  
                    'first_date':1340366753,
                    'late_date':1341737916,
                    'activity_type':u'Spamming'
                },
                {  
                    'first_date':1341153788,
                    'late_date':1343235622,
                    'activity_type':u'Malware Domain'
                },
                {  
                    'first_date':1340366753,
                    'late_date':1341737916,
                    'activity_type':u'Spamming'
                },
                {  
                    'first_date':1340366753,
                    'late_date':1341737916,
                    'activity_type':u'Spamming'
                },
                {  
                    'first_date':1340366753,
                    'late_date':1341737916,
                    'activity_type':u'Spamming'
                },
                {  
                    'first_date':1340366753,
                    'late_date':1341737916,
                    'activity_type':u'Spamming'
                },
                {  
                    'first_date':1340366753,
                    'late_date':1341737916,
                    'activity_type':u'Spamming'
                },
                {  
                    'first_date':1341419822,
                    'late_date':1343235622,
                    'activity_type':u'Malware Domain'
                },
                {  
                    'first_date':1340366753,
                    'late_date':1341737916,
                    'activity_type':u'Spamming'
                },
                {  
                    'first_date':1341499643,
                    'late_date':1341575818,
                    'activity_type':u'Malware Domain'
                },
                {  
                    'first_date':1340366753,
                    'late_date':1341737916,
                    'activity_type':u'Spamming'
                },
                {  
                    'first_date':1340366753,
                    'late_date':1341737916,
                    'activity_type':u'Spamming'
                },
                {  
                    'first_date':1341499643,
                    'late_date':1343235622,
                    'activity_type':u'Malware Domain'
                },
                {  
                    'first_date':1340366753,
                    'late_date':1341737916,
                    'activity_type':u'Spamming'
                },
                {  
                    'first_date':1340366753,
                    'late_date':1341737916,
                    'activity_type':u'Spamming'
                },
                {  
                    'first_date':1340366753,
                    'late_date':1341737916,
                    'activity_type':u'Spamming'
                },
                {  
                    'first_date':1340366753,
                    'late_date':1341737916,
                    'activity_type':u'Spamming'
                },
                {  
                    'first_date':1340366753,
                    'late_date':1341737916,
                    'activity_type':u'Spamming'
                },
                {  
                    'first_date':1340366753,
                    'late_date':1341737916,
                    'activity_type':u'Spamming'
                },
                {  
                    'first_date':1340366753,
                    'late_date':1341737916,
                    'activity_type':u'Spamming'
                },
                {  
                    'first_date':1340366753,
                    'late_date':1341737916,
                    'activity_type':u'Spamming'
                },
                {  
                    'first_date':1340366753,
                    'late_date':1341737916,
                    'activity_type':u'Spamming'
                },
                {  
                    'first_date':1340366753,
                    'late_date':1341737916,
                    'activity_type':u'Spamming'
                },
                {  
                    'first_date':1340366753,
                    'late_date':1341737916,
                    'activity_type':u'Spamming'
                },
                {  
                    'first_date':1341737916,
                    'late_date':1342955302,
                    'activity_type':u'Spamming'
                },
                {  
                    'first_date':1341737916,
                    'late_date':1342955302,
                    'activity_type':u'Spamming'
                },
                {  
                    'first_date':1341737916,
                    'late_date':1342955302,
                    'activity_type':u'Spamming'
                },
                {  
                    'first_date':1341737916,
                    'late_date':1342955302,
                    'activity_type':u'Spamming'
                },
                {  
                    'first_date':1341737916,
                    'late_date':1342955302,
                    'activity_type':u'Spamming'
                },
                {  
                    'first_date':1341737916,
                    'late_date':1342955302,
                    'activity_type':u'Spamming'
                },
                {  
                    'first_date':1341737916,
                    'late_date':1342955302,
                    'activity_type':u'Spamming'
                },
                {  
                    'first_date':1341737916,
                    'late_date':1342955302,
                    'activity_type':u'Spamming'
                },
                {  
                    'first_date':1341737916,
                    'late_date':1342955302,
                    'activity_type':u'Spamming'
                },
                {  
                    'first_date':1341737916,
                    'late_date':1342955302,
                    'activity_type':u'Spamming'
                },
                {  
                    'first_date':1341737916,
                    'late_date':1342955302,
                    'activity_type':u'Spamming'
                },
                {  
                    'first_date':1341737916,
                    'late_date':1342955302,
                    'activity_type':u'Spamming'
                },
                {  
                    'first_date':1341737916,
                    'late_date':1341737916,
                    'activity_type':u'Spamming'
                },
                {  
                    'first_date':1341737916,
                    'late_date':1341737916,
                    'activity_type':u'Spamming'
                },
                {  
                    'first_date':1341737916,
                    'late_date':1341737916,
                    'activity_type':u'Spamming'
                },
                {  
                    'first_date':1341737916,
                    'late_date':1341737916,
                    'activity_type':u'Spamming'
                },
                {  
                    'first_date':1341737916,
                    'late_date':1341737916,
                    'activity_type':u'Spamming'
                },
                {  
                    'first_date':1341737916,
                    'late_date':1341737916,
                    'activity_type':u'Spamming'
                },
                {  
                    'first_date':1341737916,
                    'late_date':1341737916,
                    'activity_type':u'Spamming'
                },
                {  
                    'first_date':1341737916,
                    'late_date':1341737916,
                    'activity_type':u'Spamming'
                },
                {  
                    'first_date':1341737916,
                    'late_date':1341737916,
                    'activity_type':u'Spamming'
                },
                {  
                    'first_date':1341737916,
                    'late_date':1341737916,
                    'activity_type':u'Spamming'
                },
                {  
                    'first_date':1341737916,
                    'late_date':1341737916,
                    'activity_type':u'Spamming'
                },
                {  
                    'first_date':1341737916,
                    'late_date':1341737916,
                    'activity_type':u'Spamming'
                },
                {  
                    'first_date':1341737916,
                    'late_date':1341737916,
                    'activity_type':u'Spamming'
                },
                {  
                    'first_date':1341737916,
                    'late_date':1341737916,
                    'activity_type':u'Spamming'
                },
                {  
                    'first_date':1341737916,
                    'late_date':1341737916,
                    'activity_type':u'Spamming'
                },
                {  
                    'first_date':1341737916,
                    'late_date':1341737916,
                    'activity_type':u'Spamming'
                },
                {  
                    'first_date':1341737916,
                    'late_date':1341737916,
                    'activity_type':u'Spamming'
                },
                {  
                    'first_date':1341737916,
                    'late_date':1341737916,
                    'activity_type':u'Spamming'
                },
                {  
                    'first_date':1341737916,
                    'late_date':1341737916,
                    'activity_type':u'Spamming'
                },
                {  
                    'first_date':1341737916,
                    'late_date':1341737916,
                    'activity_type':u'Spamming'
                },
                {  
                    'first_date':1341737916,
                    'late_date':1341737916,
                    'activity_type':u'Spamming'
                },
                {  
                    'first_date':1341737916,
                    'late_date':1341737916,
                    'activity_type':u'Spamming'
                },
                {  
                    'first_date':1341737916,
                    'late_date':1341737916,
                    'activity_type':u'Spamming'
                },
                {  
                    'first_date':1341737916,
                    'late_date':1341737916,
                    'activity_type':u'Spamming'
                },
                {  
                    'first_date':1341737916,
                    'late_date':1341737916,
                    'activity_type':u'Spamming'
                },
                {  
                    'first_date':1341737916,
                    'late_date':1341737916,
                    'activity_type':u'Spamming'
                },
                {  
                    'first_date':1341737916,
                    'late_date':1341737916,
                    'activity_type':u'Spamming'
                },
                {  
                    'first_date':1342955302,
                    'late_date':1342955302,
                    'activity_type':u'Spamming'
                },
                {  
                    'first_date':1342955302,
                    'late_date':1342955302,
                    'activity_type':u'Spamming'
                },
                {  
                    'first_date':1342955302,
                    'late_date':1342955302,
                    'activity_type':u'Spamming'
                },
                {  
                    'first_date':1342955302,
                    'late_date':1342955302,
                    'activity_type':u'Spamming'
                }
            ],
            'is_error':False,
            'is_tracked':False,
            'activity_types':[  
                u'Malicious Host',
                u'Malware Domain',
                u'C&C',
                u'Spamming'
            ],
            'last_activity':1342955302,
            'is_valid':True,
            'address':u'69.43.161.174',
            'id':u'4ea30af203b04d5a140035ce',
            'reputation_val':u'2'
            }
        )

class IPDetailsViewTest(APITestCase):
    def test_invalid_ip(self):
        client = RequestsClient()
        response = self.client.get(reverse("threat_details", ["999.999.999.999"]), format='json')

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data, "IP Address is not valid")