from django.urls import path
from backend import views

urlpatterns = [
    # path('/', views.home, name="home"),
    path('', views.dashboard, name="dashboard"),
    path('openPorts', views.openPorts, name="openPorts"),
]