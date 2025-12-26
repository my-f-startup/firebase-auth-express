Feature: Protect handlers that require authentication
  As an application developer
  I want to protect specific operations
  So that they can only be executed by authenticated users

  Scenario: Protected operation is executed by an authenticated user
    Given an authenticated user with UID "user-321"
    When the user accesses a protected operation
    Then the operation is executed

  Scenario: Protected operation is blocked for unauthenticated requests
    When an unauthenticated request accesses a protected operation
    Then the operation is blocked
    And the response status is 401
