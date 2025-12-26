Feature: Authenticate incoming requests
  As an application owner
  I want incoming requests to be authenticated
  So that only identified users can access protected operations

  Scenario: Request with a valid identity token is accepted
    Given a user with UID "user-123"
    And the user has a valid identity token
    When the user sends a request with the token
    Then the request is accepted
    And the request identity contains UID "user-123"

  Scenario: Request without an identity token is rejected
    When a request is sent without an identity token
    Then the request is rejected
    And the response status is 401

