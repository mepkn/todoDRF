from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase
from django.contrib.auth.models import User
from .models import Post
from rest_framework_simplejwt.tokens import RefreshToken

class AuthTests(APITestCase):
    def setUp(self):
        self.register_url = reverse('user-register')
        self.token_obtain_url = reverse('token_obtain_pair')
        self.logout_url = reverse('logout')
        self.user_data = {
            'username': 'testuser',
            'email': 'test@example.com',
            'password': 'testpassword123',
            'password2': 'testpassword123'
        }
        self.user = User.objects.create_user(username='existinguser', password='testpassword123')

    def test_user_registration(self):
        response = self.client.post(self.register_url, self.user_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('user', response.data)
        self.assertIn('message', response.data)

    def test_user_login(self):
        # First, register the user to ensure they exist
        self.client.post(self.register_url, self.user_data, format='json')
        login_data = {'username': self.user_data['username'], 'password': self.user_data['password']}
        response = self.client.post(self.token_obtain_url, login_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access', response.data)
        self.assertIn('refresh', response.data)

    def test_user_logout(self):
        # Login to get tokens
        login_data = {'username': self.user.username, 'password': 'testpassword123'}
        response = self.client.post(self.token_obtain_url, login_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        refresh_token = response.data['refresh']
        access_token = response.data['access']

        # Set authorization header
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')

        # Logout
        logout_response = self.client.post(self.logout_url, {'refresh_token': refresh_token}, format='json')
        self.assertEqual(logout_response.status_code, status.HTTP_205_RESET_CONTENT)

        # Verify token is blacklisted (optional, depends on if you want to test simplejwt internals)
        # Attempting to refresh token should fail if logout worked correctly by blacklisting
        refresh_attempt_response = self.client.post(reverse('token_refresh'), {'refresh': refresh_token}, format='json')
        self.assertNotEqual(refresh_attempt_response.status_code, status.HTTP_200_OK)


class PostTests(APITestCase):
    def setUp(self):
        self.user1 = User.objects.create_user(username='user1', password='password123')
        self.user2 = User.objects.create_user(username='user2', password='password123')

        self.post1_user1 = Post.objects.create(author=self.user1, title='User1 Post1', body='Body1', is_public=True)
        self.post2_user1 = Post.objects.create(author=self.user1, title='User1 Post2', body='Body2', is_public=False)
        self.post_user2 = Post.objects.create(author=self.user2, title='User2 Post', body='Body3', is_public=True)

        self.favorite_url_template = reverse('post-favorite', kwargs={'pk': 0}) # Placeholder pk
        self.user_posts_url = reverse('user-posts')
        self.user_favorites_url = reverse('user-favorite-posts')

        # Authenticate user1
        self.client.force_authenticate(user=self.user1)
        # Get tokens for user1 to simulate real auth flow for specific views if needed
        login_data = {'username': self.user1.username, 'password': 'password123'}
        token_response = self.client.post(reverse('token_obtain_pair'), login_data, format='json')
        self.access_token_user1 = token_response.data['access']


    def test_favorite_unfavorite_post(self):
        # User1 favorites User2's public post
        favorite_url = reverse('post-favorite', kwargs={'pk': self.post_user2.pk})
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.access_token_user1}')
        response = self.client.post(favorite_url, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("Post favorited successfully", response.data['message'])
        self.assertTrue(self.post_user2.favorited_by.filter(pk=self.user1.pk).exists())

        # User1 unfavorites the same post
        response = self.client.post(favorite_url, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("Post unfavorited successfully", response.data['message'])
        self.assertFalse(self.post_user2.favorited_by.filter(pk=self.user1.pk).exists())

    def test_list_user_posts(self):
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.access_token_user1}')
        response = self.client.get(self.user_posts_url, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 2) # User1 has two posts
        post_titles = [post['title'] for post in response.data]
        self.assertIn(self.post1_user1.title, post_titles)
        self.assertIn(self.post2_user1.title, post_titles)

    def test_list_favorite_posts(self):
        # User1 favorites their own post and User2's post
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.access_token_user1}')
        self.client.post(reverse('post-favorite', kwargs={'pk': self.post1_user1.pk}), format='json')
        self.client.post(reverse('post-favorite', kwargs={'pk': self.post_user2.pk}), format='json')

        response = self.client.get(self.user_favorites_url, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 2)

        favorited_post_titles = [post['title'] for post in response.data]
        self.assertIn(self.post1_user1.title, favorited_post_titles)
        self.assertIn(self.post_user2.title, favorited_post_titles)

    def test_is_favorited_in_post_serializer(self):
        # User1 favorites post_user2
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.access_token_user1}')
        self.client.post(reverse('post-favorite', kwargs={'pk': self.post_user2.pk}), format='json')

        # List all posts (which includes post_user2)
        # Note: PostViewSet list endpoint is 'post-list' if using DefaultRouter defaults
        # We need to ensure PostViewSet is registered with 'post' basename as in urls.py
        list_posts_url = reverse('post-list') # DefaultRouter creates this name
        response = self.client.get(list_posts_url, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        found_post_user2 = False
        for post_data in response.data:
            if post_data['id'] == self.post_user2.id:
                found_post_user2 = True
                self.assertTrue(post_data['is_favorited'])
            # Check a post not favorited by user1 (e.g., one of their own, not explicitly favorited in this test scope)
            elif post_data['id'] == self.post2_user1.id: # User1's own private post, not favorited yet
                 # If the setup for user1 viewing their own posts means it's not "favorited" by default
                 # Or if it's another public post not favorited by user1
                 # This assertion depends on the specific context of what posts are returned and their expected favorite state
                 # For a post not favorited by user1, is_favorited should be False.
                 # Let's assume post2_user1 (User1's own post) is not favorited by User1 in this test context.
                 self.assertFalse(post_data.get('is_favorited', False))


        self.assertTrue(found_post_user2, "Post from user2 not found in list response.")

        # Unfavorite and check again
        self.client.post(reverse('post-favorite', kwargs={'pk': self.post_user2.pk}), format='json')
        response = self.client.get(list_posts_url, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        for post_data in response.data:
            if post_data['id'] == self.post_user2.id:
                self.assertFalse(post_data['is_favorited'])
