import urllib2
import json
import re
import calendar
import time

# Known bad: 69.43.161.174
# Known good: 8.8.8.8
# Find more examples at https://www.alienvault.com/open-threat-exchange/dashboard

class IPDetails(object):
    def __init__(self, *args, **kw):
        ip = args[0]
        self.address = ip
        self.is_tracked = False
        self.is_error = False

        raw = Reputation.get_details(ip)

        if raw:
            result_json = json.loads(raw)
		
            self.id = result_json['_id']['$id']
            self.reputation_val = result_json['reputation_val']
            self.first_activity = result_json['activities'][0]['first_date']['sec']
            self.last_activity = [
                    activity for activity in result_json['activities'] if "last_date" in activity
                ][-1]['last_date']['sec']

            self.activity_types = []
            self.activities = []

            for activity in result_json['activities']:
                if activity['name'] not in self.activity_types:
                    self.activity_types.append(activity['name'])

                if "last_date" in activity and "first_date" in activity:
                    self.activities.append({
                        "activity_type": activity['name'],
                        "first_date": activity['first_date']['sec'],
                        "late_date": activity['last_date']['sec']
                    })
        else:
            self.id = ""
            self.reputation_val = 0
            self.first_activity = None
            self.last_activity = None
            self.activities = []
            self.activity_types = []

        if ip:
            self.is_valid = True
        else:
            self.is_valid = False  

        return

class Reputation(object):
    @staticmethod
    def get_details(ip):
        if ip:
            try:
			    # format: http://reputation.us.alienvault.com/panel/ip_json.php?ip=69.43.161.174

                url = "http://reputation.alienvault.com/panel/ip_json.php?ip="+ip 
                return urllib2.urlopen(url).read()
            except:
                return "fetch error"
        else:
            return None