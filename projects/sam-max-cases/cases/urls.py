from django.urls import path
from . import views

urlpatterns = [
    path('', views.CaseListCreateView.as_view(), name='case-list'),
    path('<uuid:pk>/', views.CaseDetailView.as_view(), name='case-detail'),
    path('<uuid:case_id>/evidence/', views.EvidenceListCreateView.as_view(), name='evidence-list'),
    path('<uuid:case_id>/evidence/<uuid:pk>/', views.EvidenceDetailView.as_view(), name='evidence-detail'),
    path('<uuid:case_id>/notes/', views.CaseNoteListCreateView.as_view(), name='note-list'),
    path('<uuid:case_id>/notes/<uuid:pk>/', views.CaseNoteDetailView.as_view(), name='note-detail'),
    path('search/', views.CaseSearchView.as_view(), name='case-search'),
    path('export/', views.CaseExportView.as_view(), name='case-export'),
    path('stats/', views.CaseStatsView.as_view(), name='case-stats'),
    path('bulk-update/', views.BulkUpdateView.as_view(), name='case-bulk-update'),
    path('audit-log/', views.AuditLogListView.as_view(), name='audit-log'),
    path('audit-log/<uuid:pk>/delete/', views.AuditLogDeleteView.as_view(), name='audit-log-delete'),
]
