from rest_framework import serializers
from django.contrib.auth.models import User
from django.contrib.auth.password_validation import validate_password
from .models import Post
from taggit.serializers import TagListSerializerField, TaggitSerializer

class UserRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    password2 = serializers.CharField(write_only=True, required=True)
    email = serializers.EmailField(required=True)

    class Meta:
        model = User
        fields = ('username', 'email', 'password', 'password2')

    def validate(self, attrs):
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError({"password": "Password fields didn't match."})
        return attrs

    def create(self, validated_data):
        user = User.objects.create(
            username=validated_data['username'],
            email=validated_data['email']
        )
        user.set_password(validated_data['password'])
        user.save()
        return user

class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)

    def validate_email(self, value):
        try:
            User.objects.get(email=value)
        except User.DoesNotExist:
            raise serializers.ValidationError("User with this email does not exist.")
        return value

class ResetPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    password2 = serializers.CharField(write_only=True, required=True)
    uidb64 = serializers.CharField(required=True)
    token = serializers.CharField(required=True)

    def validate(self, attrs):
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError({"password": "Password fields didn't match."})
        # Further validation of uidb64 and token will be in the view
        return attrs

class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True, validators=[validate_password])
    new_password2 = serializers.CharField(required=True)

    def validate(self, attrs):
        if attrs['new_password'] != attrs['new_password2']:
            raise serializers.ValidationError({"new_password": "New password fields didn't match."})
        return attrs

class PostSerializer(TaggitSerializer, serializers.ModelSerializer):
    author_username = serializers.ReadOnlyField(source='author.username')
    is_favorited = serializers.SerializerMethodField()
    tags = TagListSerializerField(required=False)

    class Meta:
        model = Post
        fields = ('id', 'title', 'body', 'is_public', 'author', 'author_username', 'created_at', 'updated_at', 'favorited_by', 'is_favorited', 'tags')
        read_only_fields = ('author', 'favorited_by',) # Author should be set automatically based on the logged-in user

    def get_is_favorited(self, obj):
        user = self.context['request'].user
        if user.is_authenticated:
            return obj.favorited_by.filter(pk=user.pk).exists()
        return False

    def create(self, validated_data):
        # Set author to the current logged-in user during creation
        validated_data['author'] = self.context['request'].user
        return super().create(validated_data)

    def validate_tags(self, value):
        if len(value) > 5:
            raise serializers.ValidationError("A post can have at most 5 tags.")
        return value
