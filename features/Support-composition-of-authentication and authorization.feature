Feature: Compose authentication and authorization rules
  As an application developer
  I want authentication and authorization rules to be composable
  So that access control remains clear and maintainable

  Scenario: Authentication is checked before role authorization
    When an unauthenticated request accesses a role-protected operation
    Then the request is rejected as unauthenticated
    And role authorization is not evaluated
