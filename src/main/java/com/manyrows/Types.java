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
}
