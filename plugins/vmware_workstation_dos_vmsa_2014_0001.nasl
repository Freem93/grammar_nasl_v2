#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(72040);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/07/19 00:18:13 $");

  script_cve_id("CVE-2014-1208");
  script_bugtraq_id(64994);
  script_osvdb_id(102197);
  script_xref(name:"VMSA", value:"2014-0001");

  script_name(english:"VMware Workstation 9.x < 9.0.1 VMX Process DoS (VMSA-2014-0001)");
  script_summary(english:"Checks versions of VMware Workstation");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a virtualization application that is affected by a
denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware Workstation installed on the remote host is
version 9.x prior to 9.0.1.  It is, therefore, reportedly affected by a
denial of service vulnerability due to an issue with handling invalid
ports that could allow a guest user to crash the VMX process.");
  script_set_attribute(attribute:"solution", value:"Upgrade to VMware Workstation 9.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:workstation");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

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

fix = "9.0.1";

if (version =~ "^9\." && ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  port = kb_smb_transport();

  if (report_verbosity >0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix + '\n';
    security_note(port:port, extra:report);
  }
  else security_note(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, appname, version, path);
