from django.contrib import admin

from simple_gateway.models import Service, SSOAuthenticated, SSOAuthRequest


@admin.register(Service)
class ServiceAdmin(admin.ModelAdmin):
    # a list of displayed columns name.
    list_display = (
        "name",
        # "address",
    )
    search_fields = (
        "name",
        # "address",
    )


@admin.register(SSOAuthRequest)
class SSOAuthRequestAdmin(admin.ModelAdmin):
    # a list of displayed columns name.
    list_display = (
        "service",
        "user",
        # "address",
    )
    search_fields = (
        "service",
        "user",
        # "address",
    )


@admin.register(SSOAuthenticated)
class SSOAuthenticatedAdmin(admin.ModelAdmin):
    # a list of displayed columns name.
    list_display = (
        "service",
        "user",
        # "address",
    )
    search_fields = (
        "service",
        "user",
        # "address",
    )
