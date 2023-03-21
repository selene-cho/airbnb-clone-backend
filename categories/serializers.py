from rest_framework import serializers
from .models import Category


class CategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = Category
        fields = (
            "pk", # 방을 만들 때 넣고자 하는 카테고리의 pk 보내야 함
            "name",
            "kind",
        )
