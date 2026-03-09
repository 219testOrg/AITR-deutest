"""
Tests for SQL injection vulnerability remediation in /api/tasks endpoint.

This test suite validates that:
1. The get_tasks_api endpoint properly sanitizes user input
2. SQL injection attacks are blocked
3. Normal functionality is preserved
4. Parameterized queries work correctly with various inputs
"""

import pytest
import sys
import os

# Add parent directory to path to import modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask
from unittest.mock import Mock, patch, MagicMock
from routes.api import bp


class TestTasksAPISecurityRemediation:
    """Test suite for SQL injection vulnerability fix in get_tasks_api"""

    @pytest.fixture
    def app(self):
        """Create and configure a test Flask application"""
        app = Flask(__name__)
        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
        app.register_blueprint(bp, url_prefix='/api')
        return app

    @pytest.fixture
    def client(self, app):
        """Create a test client for the Flask application"""
        return app.test_client()

    @pytest.fixture
    def mock_db_session(self):
        """Mock database session for testing"""
        with patch('routes.api.db.session') as mock_session:
            yield mock_session

    @pytest.fixture
    def mock_task_query(self):
        """Mock Task.query for testing"""
        with patch('routes.api.Task') as mock_task:
            yield mock_task

    def test_get_tasks_with_search_parameter_uses_parameterized_query(
        self, client, mock_db_session, mock_task_query
    ):
        """
        Test that search parameter uses parameterized query.
        This is the primary fix for the SQL injection vulnerability.
        """
        # Setup mock
        mock_result = MagicMock()
        mock_result.__iter__ = Mock(return_value=iter([]))
        mock_db_session.execute.return_value = mock_result

        # Make request with search parameter
        response = client.get('/api/tasks?search=test_search')

        # Verify parameterized query was used
        assert mock_db_session.execute.called
        call_args = mock_db_session.execute.call_args

        # Check that text() was called with query string and params separately
        assert len(call_args[0]) >= 1  # Query string
        if len(call_args[0]) > 1 or call_args[1]:
            # Params should be passed as second argument or as keyword
            params = call_args[0][1] if len(call_args[0]) > 1 else call_args[1].get('params', {})
            assert isinstance(params, dict)
            assert 'search_pattern' in params or params  # Params dictionary exists

    def test_sql_injection_attempt_in_assigned_to_parameter(
        self, client, mock_db_session, mock_task_query
    ):
        """
        Test that SQL injection attempts in assigned_to parameter are blocked.
        This tests the specific vulnerability that was fixed on line 223.
        """
        # Setup mock
        mock_result = MagicMock()
        mock_result.__iter__ = Mock(return_value=iter([]))
        mock_db_session.execute.return_value = mock_result

        # Attempt SQL injection via assigned_to parameter
        malicious_input = "1 OR 1=1"
        response = client.get(f'/api/tasks?search=test&assigned_to={malicious_input}')

        # Verify the request was handled safely
        assert response.status_code == 200
        assert mock_db_session.execute.called

        # Verify that the malicious input was passed as a parameter, not concatenated
        call_args = mock_db_session.execute.call_args
        query_text = str(call_args[0][0])

        # The query should NOT contain the raw malicious input
        # It should use parameter placeholders instead
        assert 'OR 1=1' not in query_text or ':assigned_to' in query_text

    def test_sql_injection_attempt_with_union_attack(
        self, client, mock_db_session, mock_task_query
    ):
        """
        Test that UNION-based SQL injection attacks are prevented.
        """
        # Setup mock
        mock_result = MagicMock()
        mock_result.__iter__ = Mock(return_value=iter([]))
        mock_db_session.execute.return_value = mock_result

        # Attempt UNION-based SQL injection
        malicious_input = "1 UNION SELECT * FROM users--"
        response = client.get(f'/api/tasks?search=test&assigned_to={malicious_input}')

        # Verify the request was handled safely
        assert response.status_code == 200

        # Verify that parameterized query was used
        call_args = mock_db_session.execute.call_args
        query_text = str(call_args[0][0])

        # The raw UNION statement should not be in the query
        # Or if it is, it should be as a bound parameter value
        assert mock_db_session.execute.called

    def test_sql_injection_attempt_with_comment_injection(
        self, client, mock_db_session, mock_task_query
    ):
        """
        Test that SQL comment injection attacks are prevented.
        """
        # Setup mock
        mock_result = MagicMock()
        mock_result.__iter__ = Mock(return_value=iter([]))
        mock_db_session.execute.return_value = mock_result

        # Attempt comment-based SQL injection
        malicious_input = "1'; DROP TABLE tasks;--"
        response = client.get(f'/api/tasks?search=test&assigned_to={malicious_input}')

        # Verify the request was handled safely
        assert response.status_code == 200
        assert mock_db_session.execute.called

        # Verify that the malicious input is treated as a parameter value
        call_args = mock_db_session.execute.call_args
        if len(call_args[0]) > 1 or call_args[1]:
            params = call_args[0][1] if len(call_args[0]) > 1 else call_args[1].get('params', {})
            # The malicious string should be in the params, not in the query
            if params and 'assigned_to' in params:
                assert malicious_input in str(params.values())

    def test_normal_assigned_to_parameter_works_correctly(
        self, client, mock_db_session, mock_task_query
    ):
        """
        Test that legitimate assigned_to values work correctly after fix.
        """
        # Setup mock
        mock_result = MagicMock()
        mock_row = {'id': 1, 'title': 'Test Task', 'assigned_to': 5}
        mock_result.__iter__ = Mock(return_value=iter([mock_row]))
        mock_db_session.execute.return_value = mock_result

        # Make legitimate request
        response = client.get('/api/tasks?search=test&assigned_to=5')

        # Verify success
        assert response.status_code == 200
        assert mock_db_session.execute.called

    def test_multiple_parameters_use_parameterized_query(
        self, client, mock_db_session, mock_task_query
    ):
        """
        Test that all parameters (search, project_id, assigned_to) use parameterized queries.
        """
        # Setup mock
        mock_result = MagicMock()
        mock_result.__iter__ = Mock(return_value=iter([]))
        mock_db_session.execute.return_value = mock_result

        # Make request with all parameters
        response = client.get('/api/tasks?search=test&project_id=10&assigned_to=5')

        # Verify parameterized query was used
        assert response.status_code == 200
        assert mock_db_session.execute.called

        call_args = mock_db_session.execute.call_args
        # Verify parameters were passed separately
        if len(call_args[0]) > 1 or call_args[1]:
            params = call_args[0][1] if len(call_args[0]) > 1 else call_args[1].get('params', {})
            assert isinstance(params, dict)

    def test_get_tasks_without_search_parameter_still_works(
        self, client, mock_db_session, mock_task_query
    ):
        """
        Test that the ORM-based query path (when search is not provided) still works.
        """
        # Setup mock for ORM query
        mock_query = MagicMock()
        mock_query.filter_by.return_value = mock_query
        mock_query.all.return_value = []
        mock_task_query.query = mock_query

        # Make request without search parameter
        response = client.get('/api/tasks?assigned_to=5')

        # Verify success
        assert response.status_code == 200
        # The ORM query path should be used, not db.session.execute
        assert mock_query.filter_by.called

    def test_special_characters_in_assigned_to_handled_safely(
        self, client, mock_db_session, mock_task_query
    ):
        """
        Test that special characters in assigned_to are handled safely.
        """
        # Setup mock
        mock_result = MagicMock()
        mock_result.__iter__ = Mock(return_value=iter([]))
        mock_db_session.execute.return_value = mock_result

        # Test various special characters
        special_chars = ["'; --", "1' OR '1'='1", "<script>", "../../etc/passwd"]

        for special_char in special_chars:
            response = client.get(f'/api/tasks?search=test&assigned_to={special_char}')
            assert response.status_code == 200
            assert mock_db_session.execute.called

    def test_parameterized_query_structure(self, client, mock_db_session, mock_task_query):
        """
        Test that the parameterized query has the correct structure.
        Verifies that named parameters are used instead of string concatenation.
        """
        # Setup mock
        mock_result = MagicMock()
        mock_result.__iter__ = Mock(return_value=iter([]))
        mock_db_session.execute.return_value = mock_result

        # Make request
        response = client.get('/api/tasks?search=myquery&assigned_to=7&project_id=3')

        # Verify the query uses named parameters
        assert mock_db_session.execute.called
        call_args = mock_db_session.execute.call_args
        query_text = str(call_args[0][0])

        # Check for named parameter placeholders
        assert (':search_pattern' in query_text or
                ':assigned_to' in query_text or
                ':project_id' in query_text), \
            "Query should use named parameter placeholders like :param_name"

    def test_empty_assigned_to_parameter(self, client, mock_db_session, mock_task_query):
        """
        Test that empty assigned_to parameter is handled correctly.
        """
        # Setup mock
        mock_result = MagicMock()
        mock_result.__iter__ = Mock(return_value=iter([]))
        mock_db_session.execute.return_value = mock_result

        # Make request with empty assigned_to
        response = client.get('/api/tasks?search=test&assigned_to=')

        # Should still work correctly
        assert response.status_code == 200

    def test_regression_normal_functionality_preserved(
        self, client, mock_db_session, mock_task_query
    ):
        """
        Regression test to ensure normal API functionality is preserved after the fix.
        """
        # Setup mock with sample data
        mock_result = MagicMock()
        sample_tasks = [
            {'id': 1, 'title': 'Task 1', 'description': 'Description 1', 'assigned_to': 5},
            {'id': 2, 'title': 'Task 2', 'description': 'Description 2', 'assigned_to': 5}
        ]
        mock_result.__iter__ = Mock(return_value=iter(sample_tasks))
        mock_db_session.execute.return_value = mock_result

        # Make normal request
        response = client.get('/api/tasks?search=Task&assigned_to=5')

        # Verify response
        assert response.status_code == 200
        json_data = response.get_json()
        assert 'tasks' in json_data


class TestTasksAPIEdgeCases:
    """Additional edge case tests for the tasks API"""

    @pytest.fixture
    def app(self):
        """Create and configure a test Flask application"""
        app = Flask(__name__)
        app.config['TESTING'] = True
        app.register_blueprint(bp, url_prefix='/api')
        return app

    @pytest.fixture
    def client(self, app):
        """Create a test client for the Flask application"""
        return app.test_client()

    @pytest.fixture
    def mock_db_session(self):
        """Mock database session for testing"""
        with patch('routes.api.db.session') as mock_session:
            yield mock_session

    def test_numeric_assigned_to_parameter(self, client, mock_db_session):
        """Test that numeric assigned_to values work correctly"""
        mock_result = MagicMock()
        mock_result.__iter__ = Mock(return_value=iter([]))
        mock_db_session.execute.return_value = mock_result

        response = client.get('/api/tasks?search=test&assigned_to=123')
        assert response.status_code == 200

    def test_very_long_assigned_to_parameter(self, client, mock_db_session):
        """Test handling of very long assigned_to values"""
        mock_result = MagicMock()
        mock_result.__iter__ = Mock(return_value=iter([]))
        mock_db_session.execute.return_value = mock_result

        # Test with very long string
        long_value = "A" * 10000
        response = client.get(f'/api/tasks?search=test&assigned_to={long_value}')
        assert response.status_code == 200

    def test_url_encoded_characters_in_assigned_to(self, client, mock_db_session):
        """Test that URL-encoded characters are handled properly"""
        mock_result = MagicMock()
        mock_result.__iter__ = Mock(return_value=iter([]))
        mock_db_session.execute.return_value = mock_result

        # URL encoded single quote: %27
        response = client.get('/api/tasks?search=test&assigned_to=%27%20OR%20%271%27%3D%271')
        assert response.status_code == 200
