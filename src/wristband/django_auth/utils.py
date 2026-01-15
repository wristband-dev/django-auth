from .models import RawUserInfo, UserInfo


def map_userinfo_claims(raw: RawUserInfo) -> UserInfo:
    """
    Maps a RawUserInfo (OIDC claim names) to UserInfo (User entity field names).

    Args:
        raw: RawUserInfo object with OIDC claim names

    Returns:
        UserInfo object with User entity field names
    """
    return UserInfo(
        user_id=raw.sub,
        tenant_id=raw.tnt_id,
        application_id=raw.app_id,
        identity_provider_name=raw.idp_name,
        full_name=raw.name,
        given_name=raw.given_name,
        family_name=raw.family_name,
        middle_name=raw.middle_name,
        nickname=raw.nickname,
        display_name=raw.preferred_username,
        picture_url=raw.picture,
        email=raw.email,
        email_verified=raw.email_verified,
        gender=raw.gender,
        birthdate=raw.birthdate,
        time_zone=raw.zoneinfo,
        locale=raw.locale,
        phone_number=raw.phone_number,
        phone_number_verified=raw.phone_number_verified,
        updated_at=raw.updated_at,
        roles=raw.roles,
        custom_claims=raw.custom_claims,
    )
