# Generated by Django 3.2 on 2023-05-26 14:20

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models

import simple_gateway.models


class Migration(migrations.Migration):
    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="Service",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("name", models.CharField(max_length=128, verbose_name="Name")),
                ("base_url", models.URLField(verbose_name="Base url")),
                ("enabled", models.BooleanField(default=False, verbose_name="Enabled")),
                (
                    "sso_token",
                    models.CharField(
                        default=simple_gateway.models.token_generator,
                        max_length=36,
                        unique=True,
                        verbose_name="SSOToken",
                    ),
                ),
            ],
        ),
        migrations.CreateModel(
            name="SSOAuthRequest",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("sso_token", models.CharField(max_length=36, verbose_name="SsoToken")),
                (
                    "auth_token",
                    models.CharField(
                        default=simple_gateway.models.token_generator,
                        max_length=36,
                        unique=True,
                        verbose_name="AuthToken",
                    ),
                ),
                (
                    "next_url",
                    models.CharField(
                        help_text="To go after success auth",
                        max_length=512,
                        verbose_name="Next url",
                    ),
                ),
                (
                    "created_at",
                    models.DateTimeField(auto_now_add=True, verbose_name="Created at"),
                ),
                (
                    "service",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        to="simple_gateway.service",
                        verbose_name="Service",
                    ),
                ),
                (
                    "user",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        to=settings.AUTH_USER_MODEL,
                        verbose_name="User",
                    ),
                ),
            ],
        ),
        migrations.CreateModel(
            name="SSOAuthenticated",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("sso_token", models.CharField(max_length=36, verbose_name="SsoToken")),
                (
                    "created_at",
                    models.DateTimeField(auto_now_add=True, verbose_name="Created at"),
                ),
                (
                    "service",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        to="simple_gateway.service",
                        verbose_name="Service",
                    ),
                ),
                (
                    "user",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        to=settings.AUTH_USER_MODEL,
                        verbose_name="User",
                    ),
                ),
            ],
        ),
    ]
