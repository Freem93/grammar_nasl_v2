#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82995);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/17 17:13:10 $");

  script_cve_id("CVE-2014-1568");
  script_bugtraq_id(70116);
  script_osvdb_id(112036);
  script_xref(name:"CERT", value:"772676");

  script_name(english:"Oracle iPlanet Web Server 7.0.x < 7.0.21 NSS Signature Verification Vulnerability");
  script_summary(english:"Checks the version in the admin console.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a signature forgery
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Oracle iPlanet Web Server
(formerly known as Sun Java System Web Server) running on the remote
host is 7.0.x prior to 7.0.21. It is, therefore, affected by a flaw in
the Network Security Services (NSS) library due to improper parsing of
ASN.1 values in an RSA signature. A man-in-the-middle attacker, using
a crafted certificate, can exploit this to forge RSA signatures, such
as SSL certificates.");
  # http://www.oracle.com/technetwork/topics/security/cpuapr2015-2365600.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?15c09d3d");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle iPlanet Web Server 7.0.21 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:iplanet_web_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:network_security_services");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("oracle_iplanet_web_server_detect.nbin");
  script_require_keys("installed_sw/Oracle iPlanet Web Server/");

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

fix = "7.0.21";
min = "7.0";

if (
  ver_compare(ver:version, fix:min, strict:FALSE) >= 0 &&
  ver_compare(ver:version, fix:fix, strict:FALSE) == -1
  )
  {
    if (report_verbosity > 0)
    {
      report =
        '\n  Version source    : ' + app_name +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 7.0.21' +
        '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, app_name, port, version);
