#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81497);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/11/23 20:42:23 $");

  script_bugtraq_id(72716);
  script_osvdb_id(118636);
  script_xref(name:"CERT", value:"366544");

  script_name(english:"Adtrustmedia PrivDog < 3.0.105.0 Security Bypass Vulnerability");
  script_summary(english:"Checks the version of PrivDog.");

  script_set_attribute(attribute:'synopsis', value:
"The remote Windows host has an application that is affected by an SSL
certificate security bypass vulnerability.");
  script_set_attribute(attribute:'description', value:
"The version of Adtrustmedia PrivDog installed on the remote Windows
host is prior to 3.0.105.0. It is, therefore, affected by a flaw in
which X.509 certificates are not properly checked to ensure that they
are not expired, revoked, or otherwise invalidated. An attacker can
exploit this vulnerability to intercept, disclose, and manipulate
HTTPS traffic.");
  script_set_attribute(attribute:'solution', value:"Upgrade PrivDog to version 3.0.105.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  # https://blog.hboeck.de/archives/865-Comodo-ships-Adware-Privdog-worse-than-Superfish.html
  script_set_attribute(attribute:'see_also', value:"http://www.nessus.org/u?5a313c30");
  script_set_attribute(attribute:'see_also', value:"http://privdog.com/advisory.html");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/02/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:adtrustmedia:privdog");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
  script_family(english:"Windows");

  script_dependencies("privdog_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/PrivDog");
  script_require_ports(139, 445);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app = "PrivDog";

install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);
ver      = install['version'];
path     = install['path'];

port = get_kb_item('SMB/transport');
if (!port) port = 445;

fix    = '3.0.105.0';
cutoff = '3.0.96.0';

if (
  ver_compare(ver:ver, fix:fix, strict:FALSE) < 0 &&
  ver_compare(ver:ver, fix:cutoff, strict:FALSE) >= 0
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port:port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, ver, path);
