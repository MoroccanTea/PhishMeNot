import unittest
from unittest.mock import Mock, patch
from check_signatures import check_signatures 

class TestCheckSignatures(unittest.TestCase):
    
    @patch('smtplib.verify')
    @patch('dkim.verify')
    @patch('dmarc.parse_dmarc_record')
    def test_check_signatures(self, mock_dmarc, mock_dkim, mock_smtplib):
        # Créez un objet email fictif pour les tests
        mock_email = Mock()
        mock_email.__getitem__.side_effect = lambda x: {'from': 'test@example.com', 'envelope-from': 'test@example.com'}.get(x)

        # Configurez le comportement attendu pour les mocks
        mock_smtplib.return_value = True  # SPF vérifié
        mock_dkim.return_value = True  # DKIM vérifié
        mock_dmarc.return_value = {'policy': 'reject'}  # DMARC vérifié

        # Appelez la fonction à tester
        result = check_signatures(mock_email)

        # Vérifiez que la fonction renvoie True comme prévu
        self.assertTrue(result)

        # Vérifiez que les mocks ont été appelés avec les bons arguments
        mock_smtplib.assert_called_once_with('test@example.com', 'test@example.com')
        mock_dkim.assert_called_once_with(mock_email.get_body("plain"), 'test@example.com', 'example.com')
        mock_dmarc.assert_called_once_with('example.com')
