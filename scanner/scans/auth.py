"""Authentication and authorization scan group metadata."""

OPTIONS = {
    "jwt", "jwtcrack", "jwtconf", "jwtkid", "jwtalg", "jwtjku",
    "auth_falsify", "auth_graph", "idor", "bfla", "diffauth", "mfabypass",
    "pwpolicy", "lockout", "accenum", "oauthpkce", "oauthstate",
}

__all__ = ["OPTIONS"]
