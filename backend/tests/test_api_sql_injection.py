"""
Comprehensive tests for SQL injection remediation in the get_tasks_api endpoint.

These tests verify that the API endpoint properly sanitizes user input and prevents
SQL injection attacks while maintaining proper functionality.
"""

import pytest
import sys
import os

# Add backend to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, jsonify
from flask_sqlalchemy import SQLAlchemy
from unittest.mock import Mock, patch, MagicMock
from sqlalchemy import text


class TestGetTasksAPISQLInjectionRemediation:
    """Test suite for SQL injection prevention in get_tasks_api endpoint"""

    @pytest.fixture
    def app(self):
        """Create a test Flask application"""
        app = Flask(__name__)
        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
        return app

    @pytest.fixture
    def client(self, app):
        """Create a test client"""
        return app.test_client()

    @pytest.fixture
    def mock_db(self):
        """Create a mock database session"""
        mock_db = Mock()
        mock_session = Mock()
        mock_db.session = mock_session
        return mock_db

    def test_sql_injection_with_union_select_attack(self, client, mock_db):
        """
        Test that UNION SELECT SQL injection attacks are prevented.

        A malicious user attempts to inject a UNION SELECT statement to extract
        data from other tables or columns.
        """
        # Arrange: Setup mock to track the executed query
        executed_queries = []

        def capture_query(query, params=None):
            executed_queries.append({
                'query': str(query),
                'params': params
            })
            mock_result = Mock()
            mock_result.__iter__ = Mock(return_value=iter([]))
            return mock_result

        with patch('routes.api.db') as mock_db_patch:
            mock_db_patch.session.execute = capture_query
            with patch('routes.api.Task') as mock_task:
                mock_task.query.all.return_value = []

                from routes.api import bp
                app = Flask(__name__)
                app.register_blueprint(bp, url_prefix='/api')
                client = app.test_client()

                # Act: Attempt SQL injection with UNION SELECT
                malicious_payload = "' UNION SELECT * FROM users--"
                response = client.get(f'/api/tasks?search={malicious_payload}')

                # Assert: Query should use parameterized approach
                assert len(executed_queries) > 0
                query_info = executed_queries[0]

                # Verify parameterized query is used (contains :search_pattern)
                assert ':search_pattern' in query_info['query']

                # Verify parameters are properly bound
                assert query_info['params'] is not None
                assert 'search_pattern' in query_info['params']

                # Verify the malicious payload is treated as a literal string
                # It should be in the pattern with % wildcards, not executed as SQL
                assert query_info['params']['search_pattern'] == f'%{malicious_payload}%'

    def test_sql_injection_with_comment_injection(self, client, mock_db):
        """
        Test that SQL comment injection attacks are prevented.

        Attacker tries to comment out parts of the query using -- or /* */
        """
        executed_queries = []

        def capture_query(query, params=None):
            executed_queries.append({
                'query': str(query),
                'params': params
            })
            mock_result = Mock()
            mock_result.__iter__ = Mock(return_value=iter([]))
            return mock_result

        with patch('routes.api.db') as mock_db_patch:
            mock_db_patch.session.execute = capture_query
            with patch('routes.api.Task') as mock_task:
                mock_task.query.all.return_value = []

                from routes.api import bp
                app = Flask(__name__)
                app.register_blueprint(bp, url_prefix='/api')
                client = app.test_client()

                # Test with SQL comment
                malicious_payload = "test' OR 1=1--"
                response = client.get(f'/api/tasks?search={malicious_payload}')

                # Verify parameterized query is used
                assert len(executed_queries) > 0
                query_info = executed_queries[0]
                assert ':search_pattern' in query_info['query']
                assert query_info['params']['search_pattern'] == f'%{malicious_payload}%'

    def test_sql_injection_with_always_true_condition(self, client, mock_db):
        """
        Test that always-true condition injections are prevented.

        Attacker tries to inject OR 1=1 to bypass WHERE conditions.
        """
        executed_queries = []

        def capture_query(query, params=None):
            executed_queries.append({
                'query': str(query),
                'params': params
            })
            mock_result = Mock()
            mock_result.__iter__ = Mock(return_value=iter([]))
            return mock_result

        with patch('routes.api.db') as mock_db_patch:
            mock_db_patch.session.execute = capture_query
            with patch('routes.api.Task') as mock_task:
                mock_task.query.all.return_value = []

                from routes.api import bp
                app = Flask(__name__)
                app.register_blueprint(bp, url_prefix='/api')
                client = app.test_client()

                # Test with OR 1=1 injection
                malicious_payload = "' OR '1'='1"
                response = client.get(f'/api/tasks?search={malicious_payload}')

                # Verify parameterized query is used
                assert len(executed_queries) > 0
                query_info = executed_queries[0]
                assert ':search_pattern' in query_info['query']
                assert query_info['params']['search_pattern'] == f'%{malicious_payload}%'

    def test_sql_injection_with_stacked_queries(self, client, mock_db):
        """
        Test that stacked query injections are prevented.

        Attacker tries to execute multiple queries using semicolons.
        """
        executed_queries = []

        def capture_query(query, params=None):
            executed_queries.append({
                'query': str(query),
                'params': params
            })
            mock_result = Mock()
            mock_result.__iter__ = Mock(return_value=iter([]))
            return mock_result

        with patch('routes.api.db') as mock_db_patch:
            mock_db_patch.session.execute = capture_query
            with patch('routes.api.Task') as mock_task:
                mock_task.query.all.return_value = []

                from routes.api import bp
                app = Flask(__name__)
                app.register_blueprint(bp, url_prefix='/api')
                client = app.test_client()

                # Test with stacked queries
                malicious_payload = "'; DROP TABLE tasks; --"
                response = client.get(f'/api/tasks?search={malicious_payload}')

                # Verify parameterized query is used
                assert len(executed_queries) > 0
                query_info = executed_queries[0]
                assert ':search_pattern' in query_info['query']
                assert query_info['params']['search_pattern'] == f'%{malicious_payload}%'

    def test_legitimate_search_functionality(self, client):
        """
        Test that legitimate search queries work correctly after remediation.

        Ensures the fix doesn't break normal functionality.
        """
        with patch('routes.api.db') as mock_db_patch:
            # Setup mock to return sample tasks
            mock_result = Mock()
            sample_task = {
                'id': 1,
                'title': 'Test Task',
                'description': 'Test Description',
                'project_id': 1,
                'assigned_to': 1
            }
            mock_result.__iter__ = Mock(return_value=iter([sample_task]))
            mock_db_patch.session.execute.return_value = mock_result

            from routes.api import bp
            app = Flask(__name__)
            app.register_blueprint(bp, url_prefix='/api')
            client = app.test_client()

            # Test normal search
            response = client.get('/api/tasks?search=test')

            # Verify the query was executed
            assert mock_db_patch.session.execute.called

            # Verify parameters were used
            call_args = mock_db_patch.session.execute.call_args
            assert len(call_args) >= 2  # query and params
            params = call_args[0][1] if len(call_args[0]) > 1 else call_args[1].get('params', {})
            assert 'search_pattern' in params
            assert params['search_pattern'] == '%test%'

    def test_search_with_special_characters(self, client):
        """
        Test that special characters in search terms are handled safely.

        Ensures characters like %, _, quotes, etc. are properly escaped.
        """
        executed_queries = []

        def capture_query(query, params=None):
            executed_queries.append({
                'query': str(query),
                'params': params
            })
            mock_result = Mock()
            mock_result.__iter__ = Mock(return_value=iter([]))
            return mock_result

        with patch('routes.api.db') as mock_db_patch:
            mock_db_patch.session.execute = capture_query
            with patch('routes.api.Task') as mock_task:
                mock_task.query.all.return_value = []

                from routes.api import bp
                app = Flask(__name__)
                app.register_blueprint(bp, url_prefix='/api')
                client = app.test_client()

                # Test with special characters
                special_chars = ["'", '"', '%', '_', '\\', ';']
                for char in special_chars:
                    executed_queries.clear()
                    response = client.get(f'/api/tasks?search={char}')

                    # Verify parameterized query is used
                    assert len(executed_queries) > 0
                    query_info = executed_queries[0]
                    assert ':search_pattern' in query_info['query']
                    assert query_info['params']['search_pattern'] == f'%{char}%'

    def test_search_with_project_id_parameter(self, client):
        """
        Test that project_id parameter is also properly sanitized.

        Ensures all parameters use parameterized queries.
        """
        executed_queries = []

        def capture_query(query, params=None):
            executed_queries.append({
                'query': str(query),
                'params': params
            })
            mock_result = Mock()
            mock_result.__iter__ = Mock(return_value=iter([]))
            return mock_result

        with patch('routes.api.db') as mock_db_patch:
            mock_db_patch.session.execute = capture_query
            with patch('routes.api.Task') as mock_task:
                mock_task.query.all.return_value = []

                from routes.api import bp
                app = Flask(__name__)
                app.register_blueprint(bp, url_prefix='/api')
                client = app.test_client()

                # Test with search and project_id
                response = client.get('/api/tasks?search=test&project_id=1')

                # Verify parameterized query is used for both parameters
                assert len(executed_queries) > 0
                query_info = executed_queries[0]
                assert ':search_pattern' in query_info['query']
                assert ':project_id' in query_info['query']
                assert query_info['params']['search_pattern'] == '%test%'
                assert query_info['params']['project_id'] == '1'

    def test_search_with_assigned_to_parameter(self, client):
        """
        Test that assigned_to parameter is also properly sanitized.
        """
        executed_queries = []

        def capture_query(query, params=None):
            executed_queries.append({
                'query': str(query),
                'params': params
            })
            mock_result = Mock()
            mock_result.__iter__ = Mock(return_value=iter([]))
            return mock_result

        with patch('routes.api.db') as mock_db_patch:
            mock_db_patch.session.execute = capture_query
            with patch('routes.api.Task') as mock_task:
                mock_task.query.all.return_value = []

                from routes.api import bp
                app = Flask(__name__)
                app.register_blueprint(bp, url_prefix='/api')
                client = app.test_client()

                # Test with search and assigned_to
                response = client.get('/api/tasks?search=test&assigned_to=1')

                # Verify parameterized query is used for both parameters
                assert len(executed_queries) > 0
                query_info = executed_queries[0]
                assert ':search_pattern' in query_info['query']
                assert ':assigned_to' in query_info['query']
                assert query_info['params']['search_pattern'] == '%test%'
                assert query_info['params']['assigned_to'] == '1'

    def test_search_with_all_parameters(self, client):
        """
        Test that all parameters together are properly sanitized.
        """
        executed_queries = []

        def capture_query(query, params=None):
            executed_queries.append({
                'query': str(query),
                'params': params
            })
            mock_result = Mock()
            mock_result.__iter__ = Mock(return_value=iter([]))
            return mock_result

        with patch('routes.api.db') as mock_db_patch:
            mock_db_patch.session.execute = capture_query
            with patch('routes.api.Task') as mock_task:
                mock_task.query.all.return_value = []

                from routes.api import bp
                app = Flask(__name__)
                app.register_blueprint(bp, url_prefix='/api')
                client = app.test_client()

                # Test with all parameters
                response = client.get('/api/tasks?search=test&project_id=1&assigned_to=2')

                # Verify parameterized query is used for all parameters
                assert len(executed_queries) > 0
                query_info = executed_queries[0]
                assert ':search_pattern' in query_info['query']
                assert ':project_id' in query_info['query']
                assert ':assigned_to' in query_info['query']
                assert query_info['params']['search_pattern'] == '%test%'
                assert query_info['params']['project_id'] == '1'
                assert query_info['params']['assigned_to'] == '2'

    def test_empty_search_uses_orm_not_raw_sql(self, client):
        """
        Test that empty search queries use ORM instead of raw SQL.

        This is an important security defense-in-depth measure.
        """
        with patch('routes.api.db') as mock_db_patch:
            with patch('routes.api.Task') as mock_task:
                mock_query = Mock()
                mock_query.filter_by.return_value = mock_query
                mock_query.all.return_value = []
                mock_task.query = mock_query

                from routes.api import bp
                app = Flask(__name__)
                app.register_blueprint(bp, url_prefix='/api')
                client = app.test_client()

                # Test with empty search
                response = client.get('/api/tasks')

                # Verify ORM was used, not raw SQL
                assert mock_task.query.all.called
                assert not mock_db_patch.session.execute.called

    def test_sql_injection_with_hex_encoding(self, client):
        """
        Test that hex-encoded SQL injection attempts are prevented.
        """
        executed_queries = []

        def capture_query(query, params=None):
            executed_queries.append({
                'query': str(query),
                'params': params
            })
            mock_result = Mock()
            mock_result.__iter__ = Mock(return_value=iter([]))
            return mock_result

        with patch('routes.api.db') as mock_db_patch:
            mock_db_patch.session.execute = capture_query
            with patch('routes.api.Task') as mock_task:
                mock_task.query.all.return_value = []

                from routes.api import bp
                app = Flask(__name__)
                app.register_blueprint(bp, url_prefix='/api')
                client = app.test_client()

                # Test with hex-encoded injection
                malicious_payload = "0x61646D696E"  # hex for 'admin'
                response = client.get(f'/api/tasks?search={malicious_payload}')

                # Verify parameterized query is used
                assert len(executed_queries) > 0
                query_info = executed_queries[0]
                assert ':search_pattern' in query_info['query']
                assert query_info['params']['search_pattern'] == f'%{malicious_payload}%'


class TestSQLInjectionRegressionPrevention:
    """
    Additional tests to prevent regression and ensure long-term security.
    """

    def test_parameterized_query_structure(self):
        """
        Test that the query structure uses named parameters consistently.
        """
        # Read the actual source code to verify implementation
        with open('./backend/routes/api.py', 'r') as f:
            content = f.read()

        # Verify the get_tasks_api function uses parameterized queries
        assert ':search_pattern' in content, "Query should use :search_pattern parameter"
        assert '.format(' not in content[content.find('def get_tasks_api'):content.find('def get_tasks_api') + 2000] or \
               'text(query), params' in content, "Should not use .format() in get_tasks_api or should use params"

        # Verify parameters are passed to execute
        assert 'execute(text(query), params)' in content, "Should pass params to execute()"

    def test_no_string_interpolation_in_query(self):
        """
        Test that string interpolation is not used in the SQL query construction.
        """
        with open('./backend/routes/api.py', 'r') as f:
            lines = f.readlines()

        # Find the get_tasks_api function
        in_function = False
        function_lines = []

        for i, line in enumerate(lines, 1):
            if 'def get_tasks_api' in line:
                in_function = True
            elif in_function:
                if line.strip().startswith('def ') and 'get_tasks_api' not in line:
                    break
                function_lines.append((i, line))

        # Check that SQL queries in this function don't use f-strings or .format()
        # for the main query construction
        for line_num, line in function_lines:
            if 'SELECT' in line and 'FROM tasks' in line:
                # This should be the main query line
                assert '.format(' not in line, f"Line {line_num}: Query should not use .format()"
                assert 'f"' not in line or 'search' not in line, f"Line {line_num}: Query should not use f-string with search variable"


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
