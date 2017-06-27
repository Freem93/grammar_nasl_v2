#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82994);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/16 14:02:51 $");

  script_cve_id("CVE-2014-1568");
  script_bugtraq_id(70116);
  script_osvdb_id(112036);
  script_xref(name:"CERT", value:"772676");

  script_name(english:"Oracle iPlanet Web Proxy Server 4.0 < 4.0.25 NSS Signature Verification Vulnerability");
  script_summary(english:"Checks the proxyd.exe product version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote proxy web server is affected by a signature forgery
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Oracle iPlanet Web Proxy
Server installed on the remote host is version 4.0 prior to 4.0.25. It
is, therefore, affected by a flaw in the Network Security Services
(NSS) library due to improper parsing of ASN.1 values in an RSA
signature. A man-in-the-middle attacker, using a crafted certificate,
can exploit this to forge RSA signatures, such as SSL certificates.

Note that Oracle iPlanet Web Proxy Server was formerly known as Sun
Java System Web Proxy Server.");
  # http://www.oracle.com/technetwork/topics/security/cpuapr2015-2365600.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?15c09d3d");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle iPlanet Web Proxy Server 4.0.25 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:iplanet_web_proxy_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("iplanet_web_proxy_installed.nbin");
  script_require_keys("installed_sw/Oracle iPlanet Web Proxy Server");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app_name = 'Oracle iPlanet Web Proxy Server';

install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
version = install['version'];
path    = install['path'];

fixed_version = '4.0.25';
min_version   = '4.0';

if (
  ver_compare(ver:version, fix:min_version, strict:FALSE) >= 0 &&
  ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1
)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fixed_version;

    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);
