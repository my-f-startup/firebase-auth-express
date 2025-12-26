Feature: Reject access when role information is missing
  As a security officer
  I want missing role information to deny access
  So that permissions are never assumed

  Scenario: User without role information cannot access a role-protected operation
    Given a user with UID "user-999"
    And the user has no roles assigned
    When the user accesses a role-protected operation
    Then the operation is blocked
    And the response status is 403
