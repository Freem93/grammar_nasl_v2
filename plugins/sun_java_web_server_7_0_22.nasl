#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84963);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/10/24 14:57:04 $");

  script_cve_id("CVE-2014-1569");
  script_bugtraq_id(71675);
  script_osvdb_id(115397);

  script_name(english:"Oracle iPlanet Web Server 6.1.x < 6.1.21 / 7.0.x < 7.0.22 NSS Signature Handling Remote Code Injection");
  script_summary(english:"Checks the version in the admin console.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a remote code injection
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Oracle iPlanet Web Server
(formerly known as Sun Java System Web Server) running on the remote 
host is 6.1.x prior to 6.1.21 or 7.0.x prior to 7.0.22. It is,
therefore, affected by a flaw in the definite_length_decoder()
function in the Network Security Services (NSS) library due to a
failure to ensure that the DER encoding of an ASN.1 length is properly 
formed when handling PKCS#1 signatures. A remote attacker, by using a
long byte sequence for an encoding, can exploit this to conduct a
data-smuggling attack or inject arbitrary code.");
  # http://www.oracle.com/technetwork/topics/security/cpujul2015-2367936.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d18c2a85");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2014/09/26/pkcs1.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle iPlanet Web Server 6.1.21 / 7.0.22 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:iplanet_web_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:network_security_services");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("oracle_iplanet_web_server_detect.nbin");
  script_require_keys("installed_sw/Oracle iPlanet Web Server");

  exit(0);
}

include("global_settings.inc");
include("audit.inc");
include("misc_func.inc");
include("install_func.inc");
include("http.inc");

app_name = "Oracle iPlanet Web Server";
port = get_http_port(default:8989);

install = get_single_install(app_name:app_name, port:port, exit_if_unknown_ver:TRUE);
version = install['version'];

fix = "7.0.22";
min = "7.0";

# Affected 6.1.x < 6.1.21 / 7.0.x < 7.0.22
if (
  version =~ "^6\.1\.([0-9]|1[0-9]|20)($|[^0-9])" ||
  (
    ver_compare(ver:version, fix:min, strict:FALSE) >= 0 &&
    ver_compare(ver:version, fix:fix, strict:FALSE) == -1
  )
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + app_name +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 6.1.21 / 7.0.22' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, app_name, port, version);
