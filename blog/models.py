from django.db import models


class UserProfile(models.Model):
    """
    A custom user profile model that intentionally mishandles passwords.
    """
    username = models.CharField(max_length=100, unique=True)
    
    password = models.CharField(max_length=100)
    
    bio = models.TextField(blank=True)
    email = models.EmailField()

    def __str__(self):
        return self.username

class Comment(models.Model):
    """
    A simple comment model.
    """
    user = models.ForeignKey(UserProfile, on_delete=models.CASCADE)
    
    # This field will be used to demonstrate Stored XSS.
    text = models.TextField()
    
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f'Comment by {self.user.username} on {self.created_at.strftime("%Y-%m-%d")}'