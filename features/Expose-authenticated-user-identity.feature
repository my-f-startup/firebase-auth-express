Feature: Expose the authenticated user identity
  As an application developer
  I want to access the authenticated user identity
  So that business logic can act on behalf of the user

  Scenario: Access the authenticated user identifier
    Given a request authenticated as UID "user-456"
    When the application handles the request
    Then the application can read the UID as "user-456"
  
  Scenario: Authenticated request contains the full identity context
    Given a request authenticated as UID "user-789"
    And the identity token contains additional attributes
    When the application handles the request
    Then the identity context is available to the application

