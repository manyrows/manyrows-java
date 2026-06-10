package com.manyrows;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

/**
 * Container for all wire-shaped record types. Use as
 * {@code import com.manyrows.Types.*;} or qualify with {@code Types.User}.
 *
 * <p>Field names match the JSON wire format (camelCase) so Jackson maps
 * directly. Nullability matches the API: required fields are primitives,
 * optional fields are boxed (or {@code null}).
 *
 * <p>Records ending in {@code Input} / {@code Update} are request bodies
 * (serialized out). {@code Update} bodies use {@link JsonInclude} so a
 * {@code null} field is omitted — leaving that attribute unchanged on a
 * PATCH — while a non-null value (including an empty list) replaces it.
 */
public final class Types {

    private Types() {}

    // ===== Delivery =====

    /**
     * Config or feature-flag value. For entries under
     * {@link DeliveryConfig#secrets}, {@code value} is always
     * {@code null}; instead {@code envelope} carries the encrypted
     * payload — pass to {@link Secrets#decryptSecret} along with your
     * workspace private JWK to recover the plaintext. Only set when
     * {@code isSet} is {@code true}.
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record ConfigItem(
            String key,
            String type,
            Object value,
            Boolean isSet,
            Object envelope
    ) {}

    /**
     * A feature-flag entry in the delivery payload. {@code roleIds}, when
     * non-empty, restricts the flag to users holding one of those roles.
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record FeatureFlag(
            String key,
            boolean enabled,
            List<String> roleIds
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
            String productId,
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

    /** A user with their roles, permissions, and field values in this app. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record UserResult(
            User user,
            List<String> roles,
            List<String> permissions,
            List<UserFieldValue> fields
    ) {}

    /** Result of provisioning a user via {@link Client#createUser}. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record CreateUserResult(
            User user,
            boolean created,
            List<String> roles,
            boolean invited
    ) {}

    /** Per-email outcome of {@link Client#batchCreateUsers}. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record BatchUserResult(
            String email,
            String userId,
            boolean created,
            String error
    ) {}

    /** Result of {@link Client#setUserStatus}. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record UserStatus(
            String userId,
            String status
    ) {}

    /** Result of {@link Client#removeUser}. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record RemoveUserResult(
            boolean removedFromApp,
            boolean identityDeleted
    ) {}

    /** A one-time passwordless sign-in link from {@link Client#createMagicLink}. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record MagicLinkResult(
            String url,
            String expiresAt
    ) {}

    /** An active session for a member in this app. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Session(
            String id,
            String createdAt,
            String lastSeenAt,
            String expiresAt,
            String userAgent,
            String ip
    ) {}

    /** One authentication-event log line. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record AuthLogEntry(
            String id,
            String createdAt,
            String event,
            String method,
            String outcome,
            String failureReason,
            String actorType,
            String ip,
            String userAgent,
            String requestId
    ) {}

    /** A page of {@link AuthLogEntry} (newest first). */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record AuthLogsPage(
            List<AuthLogEntry> logs,
            int total,
            int page,
            int pageSize
    ) {}

    /** A member's linked SSO/OAuth identity. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Identity(
            String provider,
            String providerSubject,
            String providerEmail,
            String createdAt,
            String lastLoginAt
    ) {}

    /** A WebAuthn passkey credential. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Passkey(
            String id,
            String name,
            List<String> transports,
            String createdAt,
            String lastUsedAt
    ) {}

    // ===== Organizations =====

    /** An app-scoped tenant. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Organization(
            String id,
            String appId,
            String name,
            String slug,
            String status,
            String createdAt
    ) {}

    /** One of a user's organizations + their tier ({@link Client#listOrganizationsForUser}). */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record OrgMembership(
            String id,
            String name,
            String slug,
            String orgRole
    ) {}

    /**
     * A member of an organization. {@code email} is populated by the member
     * list/add responses; the lightweight membership gate omits it.
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record OrgMember(
            String userId,
            String email,
            String orgRole,
            String status
    ) {}

    /** A pending organization invitation. {@code invitedByEmail} may be {@code null}. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record OrgInvite(
            String id,
            String email,
            String orgRole,
            String status,
            String invitedByEmail,
            String createdAt,
            String expiresAt
    ) {}

    /** Request body for {@link Client#createOrganization}; {@code slug} is optional. */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record CreateOrganizationInput(
            String name,
            String slug,
            String ownerUserId
    ) {}

    /** Patch body for {@link Client#updateOrganization}; {@code null} fields are left unchanged. */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record UpdateOrganizationInput(
            String name,
            String slug
    ) {}

    /**
     * Request body for {@link Client#addOrganizationMember}. Identify the user by
     * {@code userId} or {@code email} (one of the two); the other may be {@code null}.
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record AddOrgMemberInput(
            String userId,
            String email,
            String orgRole
    ) {}

    /**
     * Request body for {@link Client#createOrganizationInvite}. Only {@code email}
     * is required; {@code null} optional fields are omitted.
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record CreateOrgInviteInput(
            String email,
            String orgRole,
            List<String> roleIds,
            String invitedByUserId
    ) {}

    // ===== Roles & Permissions (authorization catalog) =====

    /** A role and the permission slugs it grants. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record RoleSummary(
            String slug,
            String name,
            List<String> permissions
    ) {}

    /** A single permission definition. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record PermissionSummary(
            String slug,
            String name
    ) {}

    // ===== Webhooks =====

    /**
     * A webhook subscription. {@code secret} is populated only on
     * {@link Client#createWebhook} / {@link Client#rotateWebhookSecret};
     * it is redacted ({@code null}) on every later read.
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Webhook(
            String id,
            String appId,
            String url,
            String secret,
            List<String> events,
            String status,
            String description,
            String createdAt,
            String updatedAt,
            String createdBy
    ) {}

    /** Request body for {@link Client#createWebhook}. */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record WebhookInput(
            String url,
            List<String> events,
            String description
    ) {}

    /** Patch body for {@link Client#updateWebhook}; {@code null} fields are left unchanged. */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record WebhookUpdate(
            String url,
            List<String> events,
            String status,
            String description
    ) {}

    // ===== User fields =====

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record UserField(
            String id,
            String userPoolId,
            String key,
            String valueType,
            String visibility,
            Boolean userEditable,
            String label,
            String status,
            String createdAt,
            String updatedAt,
            String createdBy
    ) {}

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record UserFieldsResponse(List<UserField> userFields) {}

    // ===== Config keys & feature-flag DEFINITIONS =====
    // (the schema; the per-app values/overrides are raw JSON / FeatureFlagOverride)

    /** A config-key definition (schema). */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record ConfigKey(
            String key,
            String exposure,
            String valueType,
            String status,
            String description
    ) {}

    /** A feature-flag definition (schema). */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record FeatureFlagDefinition(
            String key,
            String scope,
            boolean defaultEnabled,
            String status,
            String description
    ) {}

    /** This app's override for a feature flag. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record FeatureFlagOverride(
            boolean enabled,
            List<String> roles,
            String status
    ) {}

    /**
     * Request body for {@link Client#createConfigKey}. {@code exposure} is
     * {@code public|private|secret}; {@code valueType} is
     * {@code string|int|decimal|bool} (optionally suffixed {@code []}) or {@code json}.
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record ConfigKeyInput(
            String key,
            String exposure,
            String valueType,
            String description
    ) {}

    /** Patch body for {@link Client#updateConfigKey}; {@code null} fields are left unchanged. */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record ConfigKeyUpdate(
            String description,
            String exposure,
            String valueType,
            String status
    ) {}

    /** Request body for {@link Client#createFeatureFlag}. {@code scope} is {@code server|client}. */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record FeatureFlagInput(
            String key,
            String scope,
            Boolean defaultEnabled,
            String description
    ) {}

    /** Patch body for {@link Client#updateFeatureFlag}; {@code null} fields are left unchanged. */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record FeatureFlagUpdate(
            String description,
            String scope,
            Boolean defaultEnabled,
            String status
    ) {}
}
