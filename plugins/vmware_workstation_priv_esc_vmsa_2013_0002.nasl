#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(64921);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/02/04 12:02:45 $");

  script_cve_id("CVE-2013-1406");
  script_bugtraq_id(57867);
  script_osvdb_id(90019);
  script_xref(name:"VMSA", value:"2013-0002");

  script_name(english:"VMware Workstation 8.x < 8.0.5 / 9.x < 9.0.1 VMCI Privilege Escalation (VMSA-2013-0002)");
  script_summary(english:"Checks versions of VMware Workstation");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has a virtualization application that is affected by a
privilege escalation vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of VMware Workstation installed on the remote host is a
version prior to 8.0.5 / 9.0.1.  It is, therefore, reportedly affected
by a privilege escalation vulnerability in the Virtual Machine
Communication Interface (VMCI) in the 'VMCI.sys' driver. 

By exploiting this issue, a local attacker could elevate their
privileges on Windows-based hosts or Windows-based Guest Operating
Systems. 

Note that systems that have VMCI disabled are also affected by this
issue."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2013-0002.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to VMware Workstation 8.0.5 / 9.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:workstation");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

  script_dependencies("vmware_workstation_detect.nasl");
  script_require_keys("VMware/Workstation/Version", "VMware/Workstation/Path");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");

appname = 'VMware Workstation';

version = get_kb_item("VMware/Workstation/Version");
if (isnull(version)) audit(AUDIT_NOT_INST, appname);

path = get_kb_item("VMware/Workstation/Path");

fix = NULL;
if (version =~ "^8\.") fix = '8.0.5';
else if (version =~ "^9\.") fix = '9.0.1';

if (!isnull(fix) && ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  port = kb_smb_transport();

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
