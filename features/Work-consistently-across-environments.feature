Feature: Work consistently across environments
  As a developer
  I want authentication behavior to be consistent
  So that development, testing, and production behave the same way

  Scenario: Local environment behaves the same as production
    Given the application is running in a local environment
    And a valid identity token is provided
    When a request is sent
    Then authentication behaves the same as in production
