Feature: Authorize access based on user roles
  As a product owner
  I want access to sensitive operations to depend on user roles
  So that only authorized users can perform them

  Scenario: User with required role can access the operation
    Given a user with UID "admin-001"
    And the user has the role "admin"
    When the user accesses an admin-only operation
    Then the operation is executed

  Scenario: User without required role cannot access the operation
    Given a user with UID "user-002"
    And the user has the role "user"
    When the user accesses an admin-only operation
    Then the operation is blocked
    And the response status is 403

  Scenario Outline: User with any allowed role can access the operation
    Given a user with UID "<uid>"
    And the user has the role "<role>"
    When the user accesses a restricted operation
    Then the operation is executed

    Examples:
      | uid         | role     |
      | admin-003   | admin    |
      | support-007 | support  |

