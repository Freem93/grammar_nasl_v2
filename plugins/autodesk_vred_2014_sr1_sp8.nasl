#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76774);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/07/25 00:38:54 $");

  script_cve_id("CVE-2014-2967");
  script_bugtraq_id(68364);
  script_osvdb_id(108712);
  script_xref(name:"CERT", value:"402020");

  script_name(english:"Autodesk VRED Pro 2014 < SR1 SP8 Remote Code Execution");
  script_summary(english:"Checks Autodesk VRED version.");

  script_set_attribute(attribute:"synopsis", value:
"An application on the remote host is affected by a remote code
execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host has a version of Autodesk VRED Pro that is vulnerable
to an unauthenticated remote code execution via a Python API exposed
by its built-in web server. This can allow a remote attacker to
execute arbitrary code on the host.");
  script_set_attribute(attribute:"see_also", value:"http://www.autodesk.com/products/vred/overview");
  script_set_attribute(attribute:"solution", value:"Upgrade to Autodesk VRED Pro 2014 SR1 SP8 or higher.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:autodesk:vred");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("autodesk_vred_installed.nbin");
  script_require_keys("installed_sw/Autodesk VRED");
  script_require_ports(139, 445);

  exit(0);

}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app_name = 'Autodesk VRED';

get_kb_item_or_exit('installed_sw/' + app_name);

installs = get_installs(app_name:app_name);
if (installs[0] != IF_OK) audit(AUDIT_FN_FAIL, "get_installs()", installs[0]);

install_info = branch(installs[1]);

version = install_info['version'];
path    = install_info['path'];
product = install_info['Product'];

if ("Pro" >!< product) audit(AUDIT_INST_PATH_NOT_VULN, product, version, path);

fix = "6.6.8.0"; # 2014 SR1 SP8

if (version !~ "^6\." || ver_compare(ver:version, fix:fix, strict:FALSE) >= 0)
  audit(AUDIT_INST_PATH_NOT_VULN, product, version, path);

port = get_kb_item("SMB/transport");
if (!port) port = 445;

if (report_verbosity > 0)
{
  report =
    '\n  Product           : ' + product +
    '\n  Path              : ' + path +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix + '\n';
  security_hole(port:port, extra:report);
}
else security_hole(port);
