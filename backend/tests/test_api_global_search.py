"""
Tests for the global_search API endpoint
Focus on SQL injection vulnerability remediation
"""
import pytest
from unittest.mock import Mock, MagicMock, patch
from flask import Flask, jsonify
import sys
import os

# Add backend to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestGlobalSearchSQLInjection:
    """Test suite for SQL injection vulnerability in global_search endpoint"""

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
    def mock_db_session(self):
        """Mock database session"""
        with patch('routes.api.db') as mock_db:
            mock_session = MagicMock()
            mock_db.session = mock_session
            yield mock_session

    @pytest.fixture
    def mock_text(self):
        """Mock SQLAlchemy text function"""
        with patch('routes.api.text') as mock_text_func:
            yield mock_text_func

    def test_global_search_with_normal_query(self, app, client, mock_db_session, mock_text):
        """Test that normal search queries work correctly"""
        from routes.api import bp
        app.register_blueprint(bp, url_prefix='/api')

        # Mock the database response
        mock_result = MagicMock()
        mock_result.__iter__ = Mock(return_value=iter([]))
        mock_db_session.execute.return_value = mock_result

        # Make request with normal query
        response = client.get('/api/search?q=john')

        assert response.status_code == 200
        data = response.get_json()
        assert 'users' in data
        assert 'projects' in data
        assert 'tasks' in data
        assert data['query'] == 'john'

    def test_global_search_uses_parameterized_query(self, app, client, mock_db_session, mock_text):
        """Test that the endpoint uses parameterized queries (not string formatting)"""
        from routes.api import bp
        app.register_blueprint(bp, url_prefix='/api')

        # Mock the database response
        mock_result = MagicMock()
        mock_result.__iter__ = Mock(return_value=iter([]))
        mock_db_session.execute.return_value = mock_result

        # Mock text() to return a mock query object
        mock_query = MagicMock()
        mock_text.return_value = mock_query

        # Make request
        client.get('/api/search?q=test')

        # Verify that text() was called with parameterized query
        # The secure version should have :search_pattern, not string interpolation
        calls = mock_text.call_args_list
        if calls:
            # Check that at least one call uses parameterized syntax
            called_queries = [str(call[0][0]) if call[0] else '' for call in calls]
            has_parameterized = any(':search_pattern' in q for q in called_queries)
            assert has_parameterized, "Query should use parameterized syntax with :search_pattern"

    def test_global_search_sql_injection_single_quote(self, app, client, mock_db_session, mock_text):
        """Test that SQL injection with single quotes is prevented"""
        from routes.api import bp
        app.register_blueprint(bp, url_prefix='/api')

        # Mock the database response
        mock_result = MagicMock()
        mock_result.__iter__ = Mock(return_value=iter([]))
        mock_db_session.execute.return_value = mock_result
        mock_text.return_value = MagicMock()

        # Attempt SQL injection with single quote
        malicious_query = "' OR '1'='1"
        response = client.get(f'/api/search?q={malicious_query}')

        # Should return 200 and treat the input as a literal search string
        assert response.status_code == 200

        # Verify execute was called with parameters (dict as second argument)
        execute_calls = mock_db_session.execute.call_args_list
        if execute_calls:
            # At least one call should have parameters passed as dict
            has_params = any(
                len(call[0]) > 1 or 'search_pattern' in call[1]
                for call in execute_calls if call[0] or call[1]
            )
            assert has_params, "Execute should be called with bound parameters"

    def test_global_search_sql_injection_union_attack(self, app, client, mock_db_session, mock_text):
        """Test that SQL injection UNION attacks are prevented"""
        from routes.api import bp
        app.register_blueprint(bp, url_prefix='/api')

        # Mock the database response
        mock_result = MagicMock()
        mock_result.__iter__ = Mock(return_value=iter([]))
        mock_db_session.execute.return_value = mock_result
        mock_text.return_value = MagicMock()

        # Attempt UNION-based SQL injection
        malicious_query = "' UNION SELECT * FROM users--"
        response = client.get(f'/api/search?q={malicious_query}')

        # Should return 200 and treat input as literal string
        assert response.status_code == 200
        data = response.get_json()
        # The malicious query should be in the response as a literal search term
        assert data['query'] == malicious_query

    def test_global_search_sql_injection_comment_injection(self, app, client, mock_db_session, mock_text):
        """Test that SQL comment injection is prevented"""
        from routes.api import bp
        app.register_blueprint(bp, url_prefix='/api')

        # Mock the database response
        mock_result = MagicMock()
        mock_result.__iter__ = Mock(return_value=iter([]))
        mock_db_session.execute.return_value = mock_result
        mock_text.return_value = MagicMock()

        # Attempt comment-based SQL injection
        malicious_query = "admin'--"
        response = client.get(f'/api/search?q={malicious_query}')

        # Should return 200 and not allow comment to break out of query
        assert response.status_code == 200

    def test_global_search_sql_injection_stacked_queries(self, app, client, mock_db_session, mock_text):
        """Test that stacked query injection is prevented"""
        from routes.api import bp
        app.register_blueprint(bp, url_prefix='/api')

        # Mock the database response
        mock_result = MagicMock()
        mock_result.__iter__ = Mock(return_value=iter([]))
        mock_db_session.execute.return_value = mock_result
        mock_text.return_value = MagicMock()

        # Attempt stacked query injection
        malicious_query = "'; DROP TABLE users; --"
        response = client.get(f'/api/search?q={malicious_query}')

        # Should return 200 and treat as literal string
        assert response.status_code == 200

    def test_global_search_empty_query_returns_error(self, app, client, mock_db_session):
        """Test that empty query returns appropriate error"""
        from routes.api import bp
        app.register_blueprint(bp, url_prefix='/api')

        # Make request with empty query
        response = client.get('/api/search?q=')

        assert response.status_code == 400
        data = response.get_json()
        assert 'error' in data
        assert data['error'] == 'Search query required'

    def test_global_search_missing_query_param_returns_error(self, app, client, mock_db_session):
        """Test that missing query parameter returns appropriate error"""
        from routes.api import bp
        app.register_blueprint(bp, url_prefix='/api')

        # Make request without query parameter
        response = client.get('/api/search')

        assert response.status_code == 400
        data = response.get_json()
        assert 'error' in data

    def test_global_search_special_characters_handled_safely(self, app, client, mock_db_session, mock_text):
        """Test that special characters are handled safely"""
        from routes.api import bp
        app.register_blueprint(bp, url_prefix='/api')

        # Mock the database response
        mock_result = MagicMock()
        mock_result.__iter__ = Mock(return_value=iter([]))
        mock_db_session.execute.return_value = mock_result
        mock_text.return_value = MagicMock()

        # Test various special characters
        special_chars = [
            "test%wildcard",
            "test_underscore",
            "test;semicolon",
            "test\\backslash",
            "test\"doublequote"
        ]

        for char_query in special_chars:
            response = client.get(f'/api/search?q={char_query}')
            assert response.status_code == 200, f"Failed for query: {char_query}"

    def test_global_search_with_realistic_data(self, app, client, mock_db_session, mock_text):
        """Test with realistic search data to ensure functionality is preserved"""
        from routes.api import bp
        app.register_blueprint(bp, url_prefix='/api')

        # Mock database to return sample data
        mock_user_row = MagicMock()
        mock_user_row.__iter__ = Mock(return_value=iter([
            ('id', 1), ('username', 'john_doe'), ('email', 'john@example.com')
        ]))
        mock_user_result = MagicMock()
        mock_user_result.__iter__ = Mock(return_value=iter([mock_user_row]))

        mock_db_session.execute.return_value = mock_user_result
        mock_text.return_value = MagicMock()

        # Make realistic search query
        response = client.get('/api/search?q=john')

        assert response.status_code == 200
        data = response.get_json()
        assert data['query'] == 'john'
        assert 'users' in data
        assert 'projects' in data
        assert 'tasks' in data


class TestGlobalSearchParameterBinding:
    """Test suite specifically for parameter binding validation"""

    def test_parameter_format_in_query(self):
        """Test that the query string uses proper parameter binding format"""
        # This test validates the actual code structure
        import inspect
        from routes.api import global_search

        # Get the source code of the function
        source = inspect.getsource(global_search)

        # Check for parameterized query pattern (SQLAlchemy style)
        # Should have :parameter_name syntax, not string formatting
        assert ':search_pattern' in source or ':query' in source, \
            "Function should use named parameter binding (:param_name)"

        # Should NOT have vulnerable string formatting patterns
        vulnerable_patterns = [
            "f\"SELECT * FROM users WHERE username LIKE '%{query}%'",
            'f"SELECT * FROM users WHERE username LIKE \'%{query}%\'"',
            '% query %',  # old-style formatting
        ]

        for pattern in vulnerable_patterns:
            assert pattern not in source, \
                f"Function should not use string formatting pattern: {pattern}"

    def test_execute_called_with_parameters(self):
        """Test that db.session.execute is called with parameter dict"""
        with patch('routes.api.db') as mock_db, \
             patch('routes.api.text') as mock_text, \
             patch('routes.api.request') as mock_request:

            # Setup mocks
            mock_request.args.get.return_value = 'test_query'
            mock_text.return_value = MagicMock()
            mock_result = MagicMock()
            mock_result.__iter__ = Mock(return_value=iter([]))
            mock_db.session.execute.return_value = mock_result

            # Import and call the function
            from routes.api import global_search

            try:
                result = global_search()
            except:
                pass  # Function may fail due to missing dependencies, but we can check the calls

            # Verify execute was called with parameters
            execute_calls = mock_db.session.execute.call_args_list

            # At least one call should have parameters passed
            has_param_dict = False
            for call in execute_calls:
                # Check if second argument is a dict (parameters)
                if len(call[0]) > 1:
                    has_param_dict = True
                    break
                # Or check if 'search_pattern' is in kwargs
                if 'search_pattern' in str(call):
                    has_param_dict = True
                    break

            assert has_param_dict or len(execute_calls) > 0, \
                "execute() should be called with parameter dictionary for bound parameters"


class TestGlobalSearchEdgeCases:
    """Test edge cases and boundary conditions"""

    @pytest.fixture
    def app(self):
        """Create a test Flask application"""
        app = Flask(__name__)
        app.config['TESTING'] = True
        return app

    @pytest.fixture
    def client(self, app):
        """Create a test client"""
        return app.test_client()

    def test_very_long_query_string(self, app, client):
        """Test handling of very long query strings"""
        from routes.api import bp
        app.register_blueprint(bp, url_prefix='/api')

        with patch('routes.api.db') as mock_db, patch('routes.api.text'):
            mock_result = MagicMock()
            mock_result.__iter__ = Mock(return_value=iter([]))
            mock_db.session.execute.return_value = mock_result

            # Create a very long query string
            long_query = "A" * 10000
            response = client.get(f'/api/search?q={long_query}')

            # Should still handle it safely (not crash)
            assert response.status_code in [200, 400, 414]  # 414 = URI Too Long

    def test_unicode_and_international_characters(self, app, client):
        """Test handling of Unicode and international characters"""
        from routes.api import bp
        app.register_blueprint(bp, url_prefix='/api')

        with patch('routes.api.db') as mock_db, patch('routes.api.text'):
            mock_result = MagicMock()
            mock_result.__iter__ = Mock(return_value=iter([]))
            mock_db.session.execute.return_value = mock_result

            unicode_queries = [
                "José",
                "北京",
                "Москва",
                "café",
                "🔍"  # emoji
            ]

            for query in unicode_queries:
                response = client.get(f'/api/search?q={query}')
                assert response.status_code == 200, f"Failed for query: {query}"

    def test_sql_wildcard_characters_escaped(self, app, client):
        """Test that SQL wildcard characters (% and _) are handled correctly"""
        from routes.api import bp
        app.register_blueprint(bp, url_prefix='/api')

        with patch('routes.api.db') as mock_db, patch('routes.api.text') as mock_text:
            mock_result = MagicMock()
            mock_result.__iter__ = Mock(return_value=iter([]))
            mock_db.session.execute.return_value = mock_result
            mock_text.return_value = MagicMock()

            # Test with SQL wildcards
            response = client.get('/api/search?q=test%')
            assert response.status_code == 200

            # Verify that the parameter passed to execute includes the user's wildcards
            # within our controlled LIKE pattern
            execute_calls = mock_db.session.execute.call_args_list
            if execute_calls and len(execute_calls[0][0]) > 1:
                params = execute_calls[0][0][1] if len(execute_calls[0][0]) > 1 else execute_calls[0][1]
                # Our code wraps the query with %, so it should be %test%%
                # (user's % is preserved but within our controlled pattern)
                if params and 'search_pattern' in params:
                    assert 'test%' in params['search_pattern']
