#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86105);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/12/12 18:38:05 $");

  script_cve_id("CVE-2015-1793");
  script_bugtraq_id(75652);
  script_osvdb_id(124300);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuv26213");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20150710-openssl");

  script_name(english:"Cisco Prime Security Manager OpenSSL Alternative Chains Certificate Forgery (cisco-sa-20150710-openssl)");
  script_summary(english:"Checks the PRSM version.");

  script_set_attribute(attribute:"synopsis", value:
"The management application installed on the remote host is affected by
a certificate authentication bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of Cisco
Prime Security Manager installed on the remote host has a bundled
version of OpenSSL that is affected by a certificate validation bypass
vulnerability. The vulnerability exists due to a flaw in the
X509_verify_cert() function in x509_vfy.c that is triggered when
locating alternate certificate chains when the first attempt to build
such a chain fails. A remote attacker can exploit this, by using a
valid leaf certificate as a certificate authority (CA), to issue
invalid certificates that will bypass authentication.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150710-openssl
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?91e2a837");
  script_set_attribute(attribute:"see_also", value:"https://openssl.org/news/secadv/20150709.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Cisco Prime Security Manager 9.3.4.2 Build 11 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:prime_security_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("cisco_prsm_web_detect.nasl");
  script_require_keys("installed_sw/Cisco PRSM");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("audit.inc");
include("http_func.inc");
include("install_func.inc");
include("cisco_func.inc");

app = 'Cisco PRSM';

port = get_http_port(default:443);

install = get_single_install(app_name:app, port:port, exit_if_unknown_ver:TRUE);
base_url = build_url(qs:install['path'], port:port);
ver = install['version'];

fix = '9.3.4.2(11)';

# Versions 9.1.x, 9.2.x, and 9.3.x prior to 9.3.4.2 Build 11 are vulnerable
if (
  cisco_gen_ver_compare(a:ver, b:"9.1.0") >= 0 &&
  cisco_gen_ver_compare(a:ver, b:fix) < 0
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + base_url +
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, base_url, ver);
