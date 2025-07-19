<?php

namespace App\Service;

class RoleService
{
    private array $rolePermissions = [
        'ROLE_USER' => [
            'view_dashboard',
            'view_profile',
            'access_api_user'
        ],
        'ROLE_MANAGER' => [
            'view_dashboard',
            'view_profile',
            'access_api_user',
            'view_manager_panel',
            'manage_users',
            'view_reports'
        ],
        'ROLE_ADMIN' => [
            'view_dashboard',
            'view_profile',
            'access_api_user',
            'view_manager_panel',
            'manage_users',
            'view_reports',
            'view_admin_panel',
            'manage_system',
            'access_admin_api',
            'manage_permissions'
        ]
    ];

    public function hasPermission(array $userRoles, string $permission): bool {
        foreach($userRoles as $role) {
            if (isset($this->rolePermissions[$role]) &&
            in_array($permission, $this->rolePermissions[$role])) {
                return true;
            }
        }
        return false;
    }

    public function getPermissionForRole(string $role): array {
        return $this->rolePermissions[$role] ?? [];
    }

    public function getAllRoles(): array {
        return array_keys($this->rolePermissions);
    }

    public function getRoleLabel(string $role): string {
        $labels = [
            'ROLE_USER' => 'user',
            'ROLE_MANAGER' => 'manager',
            'ROLE_ADMIN' => 'admin',
            'ROLE_SUPER_ADMIN' => 'super admin'
        ];
        return $labels[$role] ?? $role;
    }
}

