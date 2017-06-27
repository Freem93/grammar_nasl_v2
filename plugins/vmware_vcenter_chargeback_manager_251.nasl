#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66897);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2013/07/26 17:13:32 $");

  script_cve_id("CVE-2013-3520");
  script_bugtraq_id(60484);
  script_osvdb_id(94188);
  script_xref(name:"EDB-ID", value:"27046");
  script_xref(name:"VMSA", value:"2013-0008");

  script_name(english:"VMware vCenter Chargeback Manager Remote Code Execution (VMSA-2013-0008)");
  script_summary(english:"Checks version of VMware vCenter Chargeback Manager");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed that is
potentially affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware vCenter Chargeback Manager installed on the
remote Windows host is potentially affected by a remote code execution
vulnerability due to a flaw in the handling of file uploads.  By
exploiting this flaw, a remote, unauthenticated attacker could execute
arbitrary code subject to the privileges of the user running the
application.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-147/");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2013-0008.html");
  script_set_attribute(attribute:"see_also", value:"http://lists.vmware.com/pipermail/security-announce/2013/000217.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to VMware vCenter Chargeback Manager 2.5.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'VMware vCenter Chargeback Manager ImageUploadServlet Arbitrary File Upload');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/14");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vcenter_chargeback_manager");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("vmware_vcenter_chargeback_manager_installed.nasl", "smb_enum_services.nasl");
  script_require_keys("SMB/VMware vCenter Chargeback Manager/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");

app = 'VMware vCenter Chargeback Manager';
port = kb_smb_transport();
version = get_kb_item_or_exit('SMB/'+app+'/Version');
path = get_kb_item_or_exit('SMB/'+app+'/Path');

status = get_kb_item_or_exit('SMB/svc/vCenterCBtomcat');
if (status != SERVICE_ACTIVE)
  exit(0, 'The '+app+' service is installed but not active.');

if (ver_compare(ver:version, fix:'2.5.1', strict:FALSE) < 0)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 2.5.1.0\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);
