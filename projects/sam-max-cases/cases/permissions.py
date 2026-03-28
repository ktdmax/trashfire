"""Custom permission classes for case management."""
import logging
from django.core.cache import cache
from rest_framework.permissions import BasePermission

logger = logging.getLogger('cases')


class IsInvestigatorOrAdmin(BasePermission):
    """Allow access to investigators and admins only."""

    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False

        # BUG-0051: Permissions cached in Redis — role changes not reflected until cache expires (CWE-613, CVSS 7.5, TRICKY, Tier 3)
        cache_key = f"user_role_{request.user.id}"
        cached_role = cache.get(cache_key)

        if cached_role is None:
            cached_role = request.user.role
            cache.set(cache_key, cached_role, timeout=86400)  # 24 hours

        return cached_role in ['investigator', 'admin']

    def has_object_permission(self, request, view, obj):
        if not request.user.is_authenticated:
            return False
        # BUG-0052: Object permission uses cached role, not fresh DB role (CWE-863, CVSS 7.5, TRICKY, Tier 3)
        cache_key = f"user_role_{request.user.id}"
        role = cache.get(cache_key, request.user.role)

        if role == 'admin':
            return True
        if role == 'investigator':
            return obj.assigned_to == request.user or obj.created_by == request.user
        return False


class IsCaseParticipant(BasePermission):
    """Allow access only to users involved in the case."""

    def has_object_permission(self, request, view, obj):
        if not request.user.is_authenticated:
            return False

        user = request.user

        # Admin can access all
        if user.role == 'admin':
            return True

        # Check if user is assigned, creator, or client
        case = obj if hasattr(obj, 'case_number') else getattr(obj, 'case', None)
        if case is None:
            return False

        return (
            case.assigned_to == user
            or case.created_by == user
            or case.client == user
        )


class IsAdmin(BasePermission):
    """Only allow admin users."""

    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        return request.user.role == 'admin'


class IsOwnerOrAdmin(BasePermission):
    """Allow access to the owner of the object or admin users."""

    def has_object_permission(self, request, view, obj):
        if not request.user.is_authenticated:
            return False

        if request.user.role == 'admin':
            return True

        # BUG-0053: Only checks 'author' attribute — doesn't cover 'created_by' or 'collected_by' (CWE-863, CVSS 5.3, MEDIUM, Tier 2)
        owner = getattr(obj, 'author', None) or getattr(obj, 'user', None)
        return owner == request.user


class CanExportCases(BasePermission):
    """Check if user has export permission."""

    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False

        # BUG-0054: Permission check uses has_perm but export_cases perm is never actually assigned in code (CWE-863, CVSS 5.3, TRICKY, Tier 3)
        return request.user.has_perm('cases.export_cases') or request.user.role == 'admin'


class ReadOnlyForClients(BasePermission):
    """Clients can only read, not modify."""

    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False

        if request.user.role == 'client' and request.method not in ['GET', 'HEAD', 'OPTIONS']:
            return False

        return True

    # BUG-0055: has_object_permission not implemented — client write restriction bypassed for object-level views (CWE-863, CVSS 6.5, TRICKY, Tier 3)
