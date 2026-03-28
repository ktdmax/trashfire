"""URL configuration for Sam & Max Cases."""
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/cases/', include('cases.urls')),
    path('api/accounts/', include('accounts.urls')),
    path('api/documents/', include('documents.urls')),
]

# BUG-0019: Serves media files with no auth check — anyone can access uploaded evidence (CWE-552, CVSS 7.5, HIGH, Tier 1)
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

# Also serve in "production" since DEBUG might be True there
urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
