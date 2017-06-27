#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84470);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/26 16:04:32 $");

  script_name(english:"TLS Version 1.0 Protocol Detection (PCI DSS)");
  script_summary(english:"Checks for the use of a deprecated TLS protocol.");

  script_set_attribute(attribute:"synopsis", value:
"The remote service encrypts traffic using a protocol with known
weaknesses.");
  script_set_attribute(attribute:"description", value:
"The remote service accepts connections encrypted using TLS 1.0. This
version of TLS is affected by multiple cryptographic flaws. An
attacker can exploit these flaws to conduct man-in-the-middle attacks
or to decrypt communications between the affected service and clients.");
  script_set_attribute(attribute:"solution", value:
"All processing and third party entities - including Acquirers,
Processors, Gateways and Service Providers must provide a TLS 1.1 or
greater service offering by June 2016. All processing and third party
entities must cutover to a secure version of TLS (as defined by NIST)
effective June 2018.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("ssl_supported_ciphers.nasl");
  script_require_keys("SSL/Supported", "Settings/PCI_DSS");

  exit(0);
}

include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssl_funcs.inc");
include("audit.inc");

if (!get_kb_item("Settings/PCI_DSS")) audit(AUDIT_PCI);
get_kb_item_or_exit("SSL/Supported");

# Get list of ports that use SSL or StartTLS.
ports = get_ssl_ports();
if (isnull(ports) || max_index(ports) == 0)
  exit(1, "The host does not appear to have any TLS-based services.");

foreach port (ports)
{
  # Get the list of encapsulations supported by the port, through either SSL or StartTLS.
  encaps = get_kb_list("SSL/Transport/" + port);
  if (!encaps)
    continue;

  ciphers = get_kb_list("SSL/Ciphers/" + port);
  if (isnull(ciphers))
    continue;

  ciphers = make_list(ciphers);
  if (max_index(ciphers) == 0)
    continue;

  tlsv1_encap = FALSE;
  tlsv1_cipher = FALSE;

  # First, determine if the server advertised any deprecated TLS/SSL versions
  foreach encap (encaps)
  {
    if (encap == ENCAPS_TLSv1)
      tlsv1_encap = TRUE;
  }

  if (!tlsv1_encap)
    continue;

  # Then, make sure that the deprecated version supports at least one cipher.
  # If zero ciphers are supported, the deprecated version cannot be used and no vulnerability exists.
  foreach cipher (ciphers)
  {
    if (tlsv1_encap && cipher =~ "^TLS1_")
      tlsv1_cipher = TRUE;

    if (tlsv1_cipher)
      break;
  }

  report = NULL;
  if (tlsv1_encap && tlsv1_cipher)
  {
    report += '\n- TLSv1 is enabled and the server supports at least one cipher.\n';
    set_kb_item(name:'SSL/deprecated/TLSv1', value:port);
  }

  if (!isnull(report))
  {
    security_warning(port:port, extra:report);
  }
}
