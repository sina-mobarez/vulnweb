# ===== IMPORTS & DEPENDENCIES =====
from django.urls import path
from . import views

# ===== API ROUTES & CONTROLLERS =====
urlpatterns = [
    path('', views.home, name='home'),
    path('register/', views.register, name='register'),
    path('login/', views.user_login, name='login'),
    path('logout/', views.user_logout, name='logout'),
    path('users/', views.user_list, name='user_list'),
    
    # Vulnerable URL pattern
    path('profile/<int:user_id>/', views.profile_view, name='profile'),
    path('profile/delete/', views.delete_profile, name='delete_profile'),

    # Vulnerable search
    path('search/', views.search, name='search'),

    # Vulnerable utility
    path('status/', views.website_status, name='website_status'),
]