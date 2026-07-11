from __future__ import annotations

from .models import BrandProfile


BRANDS: tuple[BrandProfile, ...] = (
    BrandProfile(
        name="Instagram",
        trusted_domains=("instagram.com", "www.instagram.com", "help.instagram.com"),
        keywords=("instagram", "insta", "ig login", "meta"),
    ),
    BrandProfile(
        name="Facebook",
        trusted_domains=("facebook.com", "www.facebook.com", "m.facebook.com", "fb.com"),
        keywords=("facebook", "fb login", "meta"),
    ),
    BrandProfile(
        name="Google",
        trusted_domains=("google.com", "accounts.google.com", "myaccount.google.com"),
        keywords=("google", "gmail", "google account"),
    ),
    BrandProfile(
        name="GitHub",
        trusted_domains=("github.com", "www.github.com"),
        keywords=("github", "repository", "actions secret", "developer settings"),
        bait_terms=(
            "verify account",
            "security alert",
            "collaborator request",
            "repository invite",
            "actions secret",
            "personal access token",
            "oauth app",
        ),
    ),
    BrandProfile(
        name="X/Twitter",
        trusted_domains=("x.com", "twitter.com", "www.twitter.com"),
        keywords=("twitter", "x login", "tweet"),
    ),
    BrandProfile(
        name="LinkedIn",
        trusted_domains=("linkedin.com", "www.linkedin.com"),
        keywords=("linkedin", "professional network"),
    ),
    BrandProfile(
        name="Microsoft",
        trusted_domains=("microsoft.com", "login.microsoftonline.com", "live.com"),
        keywords=("microsoft", "office 365", "outlook", "onedrive"),
    ),
    BrandProfile(
        name="Discord",
        trusted_domains=("discord.com", "discordapp.com"),
        keywords=("discord", "nitro", "server boost"),
    ),
)

