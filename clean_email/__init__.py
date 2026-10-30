"""Bot di pulizia per la posta iCloud.

Si collega a iCloud Mail solo via IMAP cifrato (TLS 1.2 o superiore, certificato
verificato), classifica la posta leggendo le sole intestazioni e applica le
regole che l'utente ha approvato. Usa solo la libreria standard di Python.
"""

__version__ = "1.0.1"
