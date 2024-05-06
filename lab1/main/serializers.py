from rest_framework import serializers
from .models import User, Token, Artwork, CustomPermission, CustomRole


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'name', 'email', 'password']
        extra_kwargs = {
            'password': {'write_only': True}
        }

    def create(self, validated_data):
        password = validated_data.pop('password', None)
        instance = self.Meta.model(**validated_data)
        if password is not None:
            instance.set_password(password)
        instance.save()
        return instance
    
class TokenSerializer(serializers.ModelSerializer):
    class Meta:
        model = Token
        fields = '__all__'

    def create(self, validated_data):
        return Token.objects.create(**validated_data)

# Отображение списка картин только с названием
class ArtworksListSerializer(serializers.ModelSerializer):
    #artists = UserSerializer(read_only=True, many=True)
    class Meta:
        model = Artwork
        fields = ['id', 'title']

# Вся инфа о картине
class ArtworksDetailListSerializer(serializers.ModelSerializer):
    artists = UserSerializer(read_only=True, many=True)
    class Meta:
        model = Artwork
        fields = "__all__"

# создание картины
class ArtworkCreateSerializer(serializers.ModelSerializer):
    artists = serializers.PrimaryKeyRelatedField(queryset=User.objects.all(), many=True)
    class Meta:
        model = Artwork
        fields = ['id', 'title', 'description', 'artists']

# Сериализатор для разрешений
class PermissionSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomPermission
        fields = "__all__"

# Отображение ролей
class RoleListSerializer(serializers.ModelSerializer):
    permissions = PermissionSerializer(read_only=True, many=True)
    users = UserSerializer(read_only=True, many=True)

    class Meta:
        model = CustomRole
        fields = "__all__"

# создание роли
class RoleCreateSerializer(serializers.ModelSerializer):
    #users = serializers.PrimaryKeyRelatedField(queryset=User.objects.all(), many=True)
    permissions = serializers.PrimaryKeyRelatedField(queryset=CustomPermission.objects.all(), many=True)

    class Meta:
        model = CustomRole
        fields = "__all__"

# Создание книги
class BookCreateSerializer(serializers.ModelSerializer):
    artists = serializers.PrimaryKeyRelatedField(queryset=User.objects.all(), many=True)

    class Meta:
        model = Artwork
        fields = "__all__"