from rest_framework import serializers
from threat import IPDetails

class DetailsSerializer(serializers.Serializer):
    is_valid = serializers.ReadOnlyField()
    address = serializers.ReadOnlyField()
    is_tracked = serializers.ReadOnlyField()
    is_error = serializers.ReadOnlyField()
    id = serializers.ReadOnlyField()
    reputation_val = serializers.ReadOnlyField()
    first_activity = serializers.ReadOnlyField()
    last_activity = serializers.ReadOnlyField()
    activities = serializers.ReadOnlyField()
    activity_types = serializers.ReadOnlyField()
    is_valid = serializers.ReadOnlyField()
