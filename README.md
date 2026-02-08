kerberos-auth-tester es una herramienta en Python diseñada para validar credenciales Kerberos utilizando hashes NTLM.
Incluye soporte para password spraying con NTLM hashes, una funcionalidad poco común y especialmente útil en escenarios de pentesting, análisis forense y troubleshooting en Active Directory.

Características principales:

- Validación de usuario + NT hash (Overpass-the-Hash)
- Password spraying con NTLM hashes
- Manejo detallado de errores Kerberos
- Código ligero, portable y fácil de integrar en otras herramientas

Ideal para:

- Pentesters que necesiten validar hashes sin iniciar sesiones SMB/RPC
- Analistas forenses que trabajen con dumps de memoria o credenciales parciales
- Troubleshooting de autenticación Kerberos en entornos AD
