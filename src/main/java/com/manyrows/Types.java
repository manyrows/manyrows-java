package com.manyrows;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

/**
 * Container for all wire-shaped record types. Use as
 * {@code import com.manyrows.Types.*;} or qualify with {@code Types.User}.
 *
 * <p>Field names match the JSON wire format (camelCase) so Jackson maps
 * directly. Nullability matches the API: required fields are primitives,
 * optional fields are boxed (or {@code null}).
 */
public final class Types {

    private Types() {}

    // ===== Delivery =====

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record ConfigItem(
            String key,
            String type,
            Object value,
            Boolean isSet
    ) {}

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record FeatureFlag(
            String key,
            boolean enabled
    ) {}

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record DeliveryConfig(
            @JsonProperty("public") List<ConfigItem> publicItems,
            @JsonProperty("private") List<ConfigItem> privateItems,
            List<ConfigItem> secrets
    ) {}

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record DeliveryFlags(
            List<FeatureFlag> client,
            List<FeatureFlag> server
    ) {}

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Delivery(
            String workspaceId,
            String projectId,
            String appId,
            String updatedAt,
            DeliveryConfig config,
            DeliveryFlags flags
    ) {}

    // ===== Permissions =====

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record PermissionResult(
            boolean allowed,
            String permission,
            String accountId
    ) {}

    // ===== Members =====

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Member(
            String userId,
            String email,
            boolean enabled,
            String source,
            String addedAt,
            List<String> roles,
            String name,
            String emailVerifiedAt,
            String passwordSetAt,
            String lastLoginAt
    ) {}

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record MembersResult(
            List<Member> members,
            int total,
            int page,
            int pageSize
    ) {}

    // ===== Users =====

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record User(
            String id,
            String email,
            boolean enabled,
            String source,
            String emailVerifiedAt,
            String passwordSetAt,
            Boolean totpEnabled
    ) {}

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record UserFieldValue(
            String id,
            String userFieldId,
            Object value,
            String updatedAt,
            String projectId,
            String userId,
            String updatedBy
    ) {}

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record UserResult(
            User user,
            List<String> roles,
            List<String> permissions,
            List<UserFieldValue> fields
    ) {}

    // ===== User Fields =====

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record UserField(
            String id,
            String key,
            String valueType,
            String status,
            String label,
            String visibility
    ) {}

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record UserFieldsResponse(List<UserField> userFields) {}

    // ===== BFF =====

    /**
     * Wire shape returned by every {@link BffClient} auth call. The
     * customer's backend stashes {@code sessionId} in a browser-facing
     * HttpOnly cookie and forwards it back via {@code X-BFF-Session-ID}
     * (handled by {@link BffClient#proxyGet}, {@code proxyPost}, etc.)
     * on every authed AppKit request thereafter.
     *
     * <p>{@code expiresAt} is informational — the BFF can use it to set
     * its cookie's {@code Max-Age} but ManyRows is the authority on
     * session lifetime.
     *
     * <p>{@code totpRequired} (with {@code challengeToken}) is set when
     * the user has TOTP enrolled — the customer's UI prompts for the
     * 6-digit code and calls {@link BffClient#verifyTotp}. No session is
     * issued yet on this branch.
     *
     * <p>{@code totpSetupRequired} is set when {@code app.Require2FA} is
     * on but the user hasn't enrolled a TOTP yet. The session IS issued;
     * the customer's UI should route to a TOTP-setup screen.
     *
     * <p>{@code passwordAlreadySet} is set on the verify-OTP path
     * (registration-via-OTP) when the verifying user already has a
     * password configured — the customer's create-account UI uses this
     * to skip the post-verify "set your password" screen instead of
     * showing it and then erroring.
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record BffSession(
            String sessionId,
            String userId,
            String expiresAt,
            Boolean totpRequired,
            String challengeToken,
            Boolean totpSetupRequired,
            Boolean passwordAlreadySet
    ) {
        /** Convenience: {@code true} when {@code totpRequired == TRUE}. */
        public boolean isTotpRequired() {
            return Boolean.TRUE.equals(totpRequired);
        }

        /** Convenience: {@code true} when {@code totpSetupRequired == TRUE}. */
        public boolean isTotpSetupRequired() {
            return Boolean.TRUE.equals(totpSetupRequired);
        }

        /** Convenience: {@code true} when {@code passwordAlreadySet == TRUE}. */
        public boolean isPasswordAlreadySet() {
            return Boolean.TRUE.equals(passwordAlreadySet);
        }
    }
}
