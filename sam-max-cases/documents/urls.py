from django.urls import path
from . import views

urlpatterns = [
    path('', views.DocumentListView.as_view(), name='document-list'),
    path('generate/', views.DocumentGenerateView.as_view(), name='document-generate'),
    path('<uuid:pk>/download/', views.DocumentDownloadView.as_view(), name='document-download'),
    path('evidence/<uuid:pk>/download/', views.EvidenceDownloadView.as_view(), name='evidence-download'),
    path('fetch-external/', views.ExternalDocumentFetchView.as_view(), name='fetch-external'),
]
