from django.shortcuts import render, redirect, get_object_or_404
from django.db import connection
from django.views.decorators.csrf import csrf_exempt
import requests

from .models import UserProfile, Comment

# ===== CORE BUSINESS LOGIC & VIEWS =====

def home(request):
    return render(request, 'insecure_app/home.html')

def register(request):
    if request.method == 'POST':
        # No input validation or cleaning
        username = request.POST['username']
        password = request.POST['password']
        email = request.POST['email']
        
        # VULNERABILITY: A02:2021 - Cryptographic Failures
        # EXPLANATION: Saving the password in plain text directly to the database.
        user = UserProfile(username=username, password=password, email=email)
        user.save()
        return redirect('login')
    return render(request, 'insecure_app/register.html')

def user_login(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        try:
            # VULNERABILITY: A02:2021 - Cryptographic Failures
            # EXPLANATION: Comparing plain text passwords. Prone to timing attacks.
            user = UserProfile.objects.get(username=username, password=password)
            request.session['user_id'] = user.id
            return redirect('profile', user_id=user.id)
        except UserProfile.DoesNotExist:
            return render(request, 'insecure_app/login.html', {'error': 'Invalid credentials'})
    return render(request, 'insecure_app/login.html')

def user_logout(request):
    request.session.flush()
    return redirect('home')

def user_list(request):
    users = UserProfile.objects.all()
    return render(request, 'insecure_app/user_list.html', {'users': users})

def profile_view(request, user_id):
    # VULNERABILITY: A01:2021 - Broken Access Control (IDOR)
    # EXPLANATION: Any authenticated or unauthenticated user can view any other
    # user's profile by simply changing the `user_id` in the URL. There is no
    # check to see if the logged-in user is the owner of the profile.
    # FIX: Check if `request.session['user_id'] == user_id` before showing sensitive data.
    profile = get_object_or_404(UserProfile, pk=user_id)
    
    # Stored XSS vulnerability handling
    if request.method == 'POST' and 'user_id' in request.session:
        comment_text = request.POST.get('comment')
        Comment.objects.create(user_id=request.session['user_id'], text=comment_text)
        return redirect('profile', user_id=user_id)

    comments = Comment.objects.all().order_by('-created_at')
    
    return render(request, 'insecure_app/profile.html', {'profile': profile, 'comments': comments})

@csrf_exempt # Disabling CSRF protection for demonstration
def delete_profile(request):
    # VULNERABILITY: A07:2021 - Identification and Authentication Failures (CSRF)
    # EXPLANATION: The @csrf_exempt decorator disables Django's built-in protection.
    # An attacker could trick a logged-in user into visiting a malicious website
    # which contains a hidden form that submits a POST request to this endpoint,
    # deleting the user's account without their consent.
    # FIX: Remove @csrf_exempt and use `{% csrf_token %}` in the form.
    if request.method == 'POST' and 'user_id' in request.session:
        user_id = request.session['user_id']
        UserProfile.objects.filter(pk=user_id).delete()
        request.session.flush()
        return redirect('home')
    return redirect('home') # Should be a confirmation page

def search(request):
    query = request.GET.get('q', '')
    results = []
    if query:
        # VULNERABILITY: A03:2021 - Injection (SQL Injection)
        # EXPLANATION: The SQL query is constructed using an f-string with raw user input.
        # This allows an attacker to manipulate the query. For example, a query of `test' OR '1'='1`
        # would return all users.
        # FIX: Always use the Django ORM or parameterized queries.
        with connection.cursor() as cursor:
            cursor.execute(f"SELECT id, username FROM insecure_app_userprofile WHERE username LIKE '%{query}%'")
            rows = cursor.fetchall()
            for row in rows:
                results.append({'id': row[0], 'username': row[1]})

    # The `query` variable is passed directly to the template for Reflected XSS.
    return render(request, 'insecure_app/search.html', {'results': results, 'query': query})

def website_status(request):
    url = request.GET.get('url', '')
    status = ''
    if url:
        # VULNERABILITY: A10:2021 - Server-Side Request Forgery (SSRF)
        # EXPLANATION: The server blindly makes a GET request to any URL provided by the user.
        # An attacker can use this to scan the internal network (e.g., http://127.0.0.1:8001),
        # access cloud provider metadata (http://169.254.169.254), or access local files (file:///etc/passwd).
        # FIX: Validate the URL against a strict allow-list of domains or IP ranges.
        try:
            response = requests.get(url, timeout=3)
            status = f"'{url}' is up with status code {response.status_code}."
        except requests.RequestException as e:
            status = f"Failed to reach '{url}': {e}"
    
    return render(request, 'insecure_app/website_status.html', {'status': status})