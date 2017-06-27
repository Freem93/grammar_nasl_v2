#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84806);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/22 04:41:10 $");

  script_cve_id("CVE-2015-3650");
  script_bugtraq_id(75686);
  script_osvdb_id(124364);
  script_xref(name:"VMSA", value:"2015-0005");

  script_name(english:"VMware Workstation 10.x < 10.0.7 / 11.x < 11.1.1 DACL Privilege Escalation (VMSA-2015-0005)");
  script_summary(english:"Checks the VMware Workstation version.");

  script_set_attribute(attribute:"synopsis", value:
"The virtualization application installed on the remote host is
affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware Workstation installed on the remote host is 10.x
prior to 10.0.7 or 11.x prior to 11.1.1. It is, therefore, affected by
a privilege escalation vulnerability due to a failure to provide a
valid discretionary access control list (DACL) pointer for the
printproxy.exe process. A local attacker, using thread injection, can
exploit this to gain elevated privileges or execute arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2015-0005.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware Workstation version 10.0.7 / 11.1.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:workstation");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("vmware_workstation_detect.nasl");
  script_require_keys("SMB/Registry/Enumerated", "VMware/Workstation/Version", "VMware/Workstation/Path");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

appname = 'VMware Workstation';

version = get_kb_item("VMware/Workstation/Version");
if (isnull(version)) audit(AUDIT_NOT_INST, appname);

path = get_kb_item_or_exit("VMware/Workstation/Path");

fix = '';

if (version =~ "^10\.")
  fix  = "10.0.7";

if (version =~ "^11\.")
  fix  = "11.1.1";

if (!empty(fix) && ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity >0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, appname, version, path);
