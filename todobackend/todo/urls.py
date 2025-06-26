from django.urls import path
from .views import (
    UserRegistrationView,
    ForgotPasswordView,
    ResetPasswordView,
    ChangePasswordView,
    PostViewSet,
    FavoritePostView,
    UserPostsView,
    FavoritePostsView,
    CommentViewSet
)
from rest_framework.routers import DefaultRouter
from rest_framework_nested import routers

router = DefaultRouter()
router.register(r'posts', PostViewSet, basename='post')

posts_router = routers.NestedSimpleRouter(router, r'posts', lookup='post')
posts_router.register(r'comments', CommentViewSet, basename='post-comments')

urlpatterns = [
    path('register/', UserRegistrationView.as_view(), name='user-register'),
    path('forgot-password/', ForgotPasswordView.as_view(), name='forgot-password'),
    path('reset-password/', ResetPasswordView.as_view(), name='reset-password'), # Typically would include uidb64 and token in path
    path('change-password/', ChangePasswordView.as_view(), name='change-password'),
    path('posts/<int:pk>/favorite/', FavoritePostView.as_view(), name='post-favorite'),
    path('user/posts/', UserPostsView.as_view(), name='user-posts'),
    path('user/favorites/', FavoritePostsView.as_view(), name='user-favorite-posts'),
] + router.urls + posts_router.urls # Add router urls to the urlpatterns
