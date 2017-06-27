#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71534);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/09/15 13:52:58 $");

  script_osvdb_id(99595);

  script_name(english:"SuperMicro Device Uses Default SSL Certificate");
  script_summary(english:"Checks if the device is using default certificate.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is using the default SSL certificate for this
service, whose private key is public knowledge.");
  script_set_attribute(attribute:"description", value:
"The X.509 certificate of the remote host has not been changed from the
default certificate that is hardwired into the firmware.  The private
key corresponding to this certificate is shared across all devices
running the same firmware, meaning that the remote host's X.509
certificate cannot be trusted.");
  # https://community.rapid7.com/community/metasploit/blog/2013/11/06/supermicro-ipmi-firmware-vulnerabilities
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?99a8b71e");
  script_set_attribute(attribute:"solution", value:"Configure the device to use a device-specific certificate.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:UC");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:supermicro:bmc");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("ssl_supported_versions.nasl");
  script_require_keys("SSL/Supported");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("x509_func.inc");

get_kb_item_or_exit("SSL/Supported");

# Parse the SuperMicro certificate before forking.
supermicro = "
MIID9TCCA16gAwIBAgIJAITpG2vqpro2MA0GCSqGSIb3DQEBBQUAMIGuMQswCQYD
VQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTERMA8GA1UEBxMIU2FuIEpvc2Ux
IjAgBgNVBAoTGVN1cGVyIE1pY3JvIENvbXB1dGVyIEluYy4xHDAaBgNVBAsTE1Nv
ZnR3YXJlIERlcGFydG1lbnQxDTALBgNVBAMTBElQTUkxJjAkBgkqhkiG9w0BCQEW
F2xpbmRhLnd1QHN1cGVybWljcm8uY29tMB4XDTEyMDQxMjAyMTkzOVoXDTE0MDQx
MjAyMTkzOVowga4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMREw
DwYDVQQHEwhTYW4gSm9zZTEiMCAGA1UEChMZU3VwZXIgTWljcm8gQ29tcHV0ZXIg
SW5jLjEcMBoGA1UECxMTU29mdHdhcmUgRGVwYXJ0bWVudDENMAsGA1UEAxMESVBN
STEmMCQGCSqGSIb3DQEJARYXbGluZGEud3VAc3VwZXJtaWNyby5jb20wgZ8wDQYJ
KoZIhvcNAQEBBQADgY0AMIGJAoGBALWrWRHpyFYt/CykPzgCzLLoQVXpJhEbL+Ag
uxga2f2QJCLZEWhs3FLkK+mFsZaf0P2fmAmlNVYtZvcvAnEa4EpJGPbCscuV6PPD
qRKYX7fEUK4x/FUVKPxMzwmqU6ozVzqW8fYxJec3ukkFVx6Q0psFQR+m1qQ9J6NK
2WNtd5xLAgMBAAGjggEXMIIBEzAdBgNVHQ4EFgQUVrmSWBEvjnqdBbkK4bj32MdV
bz0wgeMGA1UdIwSB2zCB2IAUVrmSWBEvjnqdBbkK4bj32MdVbz2hgbSkgbEwga4x
CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMREwDwYDVQQHEwhTYW4g
Sm9zZTEiMCAGA1UEChMZU3VwZXIgTWljcm8gQ29tcHV0ZXIgSW5jLjEcMBoGA1UE
CxMTU29mdHdhcmUgRGVwYXJ0bWVudDENMAsGA1UEAxMESVBNSTEmMCQGCSqGSIb3
DQEJARYXbGluZGEud3VAc3VwZXJtaWNyby5jb22CCQCE6Rtr6qa6NjAMBgNVHRME
BTADAQH/MA0GCSqGSIb3DQEBBQUAA4GBAAFJX8cnXFvvSvH8MCV8kKxw6LPOfDXA
pgbqw8sJtXGGD2qel9AA93hny2zk0jJflXhqEkdLJbiRl2cBzjSRv47gCOnL0o3/
zbds6iOpufJE3CeP1IWDJjCTC2E3aW7h8khjJOtAn70Jcs1E3NFbbDUFw/QlQs3W
pfJ72cJhQtvL";

supermicro = str_replace(string:supermicro, find:'\n', replace:"");
supermicro = base64_decode(str:supermicro);
supermicro = parse_der_cert(cert:supermicro);

if (isnull(supermicro))
  exit(1, "Failed to parse builtin certificate.");

# Get list of ports that use SSL or StartTLS.
port = get_ssl_ports(fork:TRUE);
if (isnull(port))
  exit(1, "The host does not appear to have any SSL-based services.");

# Get the certificate chain from the target.
cert = get_server_cert(port:port, encoding:"der");
if (isnull(cert))
  exit(1, "Failed to retrieve the certificate from port " + port + ".");

cert = parse_der_cert(cert:cert);
if (isnull(cert))
  exit(1, "Failed to parse certificate on port " + port + ".");

# We're mainly worried about the same public key being used, so we'll
# ignore other things like the subject, issuer, and serial number.
key1 = cert["tbsCertificate"]["subjectPublicKeyInfo"];
key2 = supermicro["tbsCertificate"]["subjectPublicKeyInfo"];
if (!obj_cmp(key1, key2))
  exit(0, "The certificate from port " + port + " is not affected.");

# Report our findings.
report = NULL;
if (report_verbosity > 0)
{
  report =
    '\n' + 'This SSL key is used by other devices, and therefore cannot be trusted :' +
    '\n' +
    '\n  Algorithm  : RSA Encryption' +
    '\n  Key Length : 1024 bits' +
    '\n  Public Key : B5 AB 59 11 E9 C8 56 2D FC 2C A4 3F 38 02 CC B2' +
    '\n               E8 41 55 E9 26 11 1B 2F E0 20 BB 18 1A D9 FD 90' +
    '\n               24 22 D9 11 68 6C DC 52 E4 2B E9 85 B1 96 9F D0' +
    '\n               FD 9F 98 09 A5 35 56 2D 66 F7 2F 02 71 1A E0 4A' +
    '\n               49 18 F6 C2 B1 CB 95 E8 F3 C3 A9 12 98 5F B7 C4' +
    '\n               50 AE 31 FC 55 15 28 FC 4C CF 09 AA 53 AA 33 57' +
    '\n               3A 96 F1 F6 31 25 E7 37 BA 49 05 57 1E 90 D2 9B' +
    '\n               05 41 1F A6 D6 A4 3D 27 A3 4A D9 63 6D 77 9C 4B' +
    '\n  Exponent   : 01 00 01' +
    '\n';
}

security_warning(port:port, extra:report);
