from django.urls import path
from . import views

urlpatterns = [
    path('encrypt_decrypt/', views.encrypt_decrypt_view, name='encrypt_decrypt'),
]
