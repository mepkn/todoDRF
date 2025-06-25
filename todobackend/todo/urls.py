from django.urls import path
from .views import (
    UserRegistrationView,
    ForgotPasswordView,
    ResetPasswordView,
    ChangePasswordView,
    PostViewSet
)
from rest_framework.routers import DefaultRouter

router = DefaultRouter()
router.register(r'posts', PostViewSet, basename='post')

urlpatterns = [
    path('register/', UserRegistrationView.as_view(), name='user-register'),
    path('forgot-password/', ForgotPasswordView.as_view(), name='forgot-password'),
    path('reset-password/', ResetPasswordView.as_view(), name='reset-password'), # Typically would include uidb64 and token in path
    path('change-password/', ChangePasswordView.as_view(), name='change-password'),
] + router.urls # Add router urls to the urlpatterns
