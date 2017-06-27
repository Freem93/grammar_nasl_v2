#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84804);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/07/17 13:16:56 $");

  script_cve_id("CVE-2015-3650");
  script_bugtraq_id(75686);
  script_osvdb_id(124364);
  script_xref(name:"VMSA", value:"2015-0005");

  script_name(english:"VMware Horizon View Client 5.x < 5.4.2 DACL Privilege Escalation (VMSA-2015-0005)");
  script_summary(english:"Checks the VMware Horizon View Client version.");

  script_set_attribute(attribute:"synopsis", value:
"The virtualization application installed on the remote host is
affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware Horizon View Client installed on the remote host
is 5.x (with local mode) prior to 5.4.2. It is, therefore, affected by
a privilege escalation vulnerability due to a failure to provide a
valid discretionary access control list (DACL) pointer for the
printproxy.exe process. A local attacker, using thread injection, can
exploit this to gain elevated privileges or execute arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2015-0005");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware Horizon View Client 5.4.2 (with local mode) or
later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:horizon_view_client");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("vmware_horizon_view_client_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/VMware Horizon View Client");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

appname = 'VMware Horizon View Client';

install = get_single_install(app_name:appname, exit_if_unknown_ver:TRUE);

version    = install["version"];
path       = install["path"];
local_mode = install["Local Mode"];

if (local_mode == "yes")
  appname += " (with local mode)";

port = get_kb_item("SMB/transport");
if (!port) port = 445;

fix = '';

if (version =~ "^5(\.|$)" && local_mode == "yes")
  fix = "5.4.2";

if (!empty(fix) && ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Product           : ' + appname +
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version+
      '\n  Fixed version     : ' + fix + '\n';

    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, appname, version, path);
