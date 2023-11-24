import unittest
from flask import Flask, session
from api import app

class APITestCase(unittest.TestCase):
    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True

    def test_index_route(self):
        response = self.app.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content_type, "text/html; charset=utf-8")
        self.assertEqual(response.data.decode(), 'Welcome to PhishMeNot API')

    def test_analyze_url_route_valid(self):
        url = 'https://example.com'
        response = self.app.post('/analyze/url', json={'url': url, 'hostname': 'example.com'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content_type, "application/json")
        self.assertIn('status', response.json)
        self.assertIn(response.json['status'], ['safe', 'unsafe'])

    def test_analyze_url_route_invalid(self):
        url = 'not-a-valid-url'
        response = self.app.post('/analyze/url', json={'url': url, 'hostname': 'invalid'})
        self.assertEqual(response.status_code, 400)
        self.assertIn('message', response.json)
        self.assertEqual(response.json['message'], 'URL is required')

    def test_analyze_url_route_no_url(self):
        response = self.app.post('/analyze/url', json={})
        self.assertEqual(response.status_code, 400)
        self.assertIn('message', response.json)
        self.assertEqual(response.json['message'], 'URL is required')

    def test_logout_route(self):
        with self.app as client:
            client.get('/logout')
            # Test redirection after logout
            response = client.get('/logout')
            self.assertEqual(response.status_code, 302)
            self.assertTrue('Location' in response.headers)
            self.assertEqual(response.headers['Location'], 'http://localhost/')
            # Test session clearing after logout
            self.assertNotIn('google_token', session)
            self.assertNotIn('vt_api_key', session)
            self.assertNotIn('user', session)


if __name__ == '__main__':
    unittest.main()