#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(64920);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/02/04 12:02:45 $");

  script_cve_id("CVE-2013-1406");
  script_bugtraq_id(57867);
  script_osvdb_id(90019);
  script_xref(name:"VMSA", value:"2013-0002");

  script_name(english:"VMware View 4.x < 4.6.2 / 5.x < 5.1.2 VMCI Privilege Escalation (VMSA-2013-0002)");
  script_summary(english:"Checks versions of VMware View");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has a desktop solution that is affected by a privilege
escalation vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of VMware View installed on the remote host is a version
prior to 4.6.2 / 5.1.2.  It is, therefore, reportedly affected by a
privilege escalation vulnerability in the Virtual Machine Communication
Interface (VMCI) in the 'VMCI.sys' driver. 

By exploiting this issue, a local attacker could elevate their
privileges on Windows-based hosts or Windows-based Guest Operating
Systems. 

Note that systems that have VMCI disabled are also affected by this
issue."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2013-0002.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to VMware View 4.6.2 / 5.1.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:view");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

  script_dependencies("vmware_view_server_detect.nasl");
  script_require_keys("VMware/ViewServer/Installed");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");

appname = "VMware View";

installed = get_kb_item("VMware/ViewServer/Installed");
if (isnull(installed)) audit(AUDIT_NOT_INST, appname);

version = get_kb_item("VMware/ViewServer/Version");
path = get_kb_item("VMware/ViewServer/Path");

fix = NULL;
if (version =~ "^4\.") fix = '4.6.2';
else if (version =~ "^5\.") fix = '5.1.2';

if (!isnull(fix) && ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  port = kb_smb_transport();

  if (report_verbosity > 0)
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
