Feature: Fail fast when authentication infrastructure is not initialized
  As a platform engineer
  I want authentication failures to be explicit
  So that configuration issues are detected early

  Scenario: Authentication fails when identity verification is not available
    Given the application has not initialized its identity provider
    When a request is sent with an identity token
    Then the request fails
    And the failure indicates a configuration error
