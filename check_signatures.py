import smtplib 
import dkim
import dmarc

def check_signatures(mail):
  """
  Vérifie les signatures SPF, DKIM et DMARC d'un email.

  Args:
    mail: L'objet email à vérifier.

  Returns:
    True si les signatures sont correctes, False sinon.
  """

  # Récupère les informations de l'email
  from_address = mail["from"]
  envelope_from = mail["envelope-from"]
  domain = from_address.split("@")[-1]

  # Vérifie la signature SPF
  if not smtplib.verify(from_address, envelope_from):
    return False

  # Vérifie la signature DKIM
  if not dkim.verify(mail.get_body("plain"), from_address, domain):
    return False

  # Vérifie la signature DMARC
  dmarc_record = dmarc.parse_dmarc_record(domain)
  if dmarc_record["policy"] == "reject" and not dkim.verify(mail.get_body("plain"), from_address, domain):
    return False

  return True