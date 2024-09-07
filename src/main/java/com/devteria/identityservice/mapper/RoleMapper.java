package com.devteria.identityservice.mapper;

import com.devteria.identityservice.dto.request.PermissionRequest;
import com.devteria.identityservice.dto.request.UserCreationRequest;
import com.devteria.identityservice.dto.request.UserUpdateRequest;
import com.devteria.identityservice.dto.response.PermissionResponse;
import com.devteria.identityservice.dto.response.UserResponse;
import com.devteria.identityservice.entity.Permission;
import com.devteria.identityservice.entity.User;
import org.mapstruct.Mapper;
import org.mapstruct.MappingTarget;

@Mapper(componentModel = "spring")
public interface PermissionMapper {
    Permission toPermission(PermissionRequest permissionRequest);
    PermissionResponse toPermissionResponse(Permission permission);
}
