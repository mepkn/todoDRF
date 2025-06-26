from django.contrib import admin
from .models import Post

@admin.register(Post)
class PostAdmin(admin.ModelAdmin):
    list_display = ('title', 'author', 'created_at', 'is_public')
    list_filter = ('is_public', 'created_at', 'author')
    search_fields = ('title', 'body')
    # Add other configurations as needed, for example, if you want to show tags in admin:
    # readonly_fields = ('tag_list',)
    # def tag_list(self, obj):
    #     return u", ".join(o.name for o in obj.tags.all())

# Register your models here.
