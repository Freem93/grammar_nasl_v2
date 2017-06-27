#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59915);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/02/23 22:37:42 $");

  script_name(english:"MS KB2719662: Vulnerabilities in Gadgets Could Allow Remote Code Execution");
  script_summary(english:"Checks if the workaround is being used");

  script_set_attribute(
    attribute:"synopsis",
    value:
"Arbitrary code can be executed on the remote host through Desktop
Gadgets."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote version of Microsoft Windows is missing a workaround that
mitigates multiple, unspecified remote code execution vulnerabilities
caused by running insecure Gadgets.  Windows Vista and 7 are affected
by this issue.  An attacker could exploit this by tricking a user into
installing a vulnerable Gadget, resulting in arbitrary code execution."
  );
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/advisory/2719662");
  script_set_attribute(attribute:"see_also", value:"http://support.microsoft.com/kb/2719662");
  script_set_attribute(attribute:"solution", value:"Apply the workaround described in Microsoft security advisory 2719662.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
  script_dependencies("smb_hotfixes.nasl");
  script_require_ports(139, 445);
  script_require_keys("SMB/Registry/Enumerated");

  exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");
include("audit.inc");

prodname = get_kb_item_or_exit('SMB/ProductName');
if (hotfix_check_sp(vista:3, win7:2) <= 0 || 'Server 2008' >< prodname || 'Server (R) 2008' >< prodname || 'Windows Embedded' >< prodname || 'Small Business Server 2011' >< prodname)
  audit(AUDIT_OS_SP_NOT_VULN);

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
value_name = "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Windows\Sidebar\TurnOffSidebar";
value_data = get_registry_value(handle:hklm, item:value_name);
RegCloseKey(handle:hklm);
close_registry();

if (value_data == 1)
  audit(AUDIT_HOST_NOT, 'affected');
else if (isnull(value_data))
  not_found = TRUE;
else
  not_one = TRUE;

port = kb_smb_transport();

if (report_verbosity > 0)
{
  report = '\nNessus determined the workaround is not being used because the following';

  if (not_found)
    report += '\nregistry value does not exist :\n\n';
  else
    report += '\nregistry value is not set to 1 :\n\n';

  report += 'HKEY_LOCAL_MACHINE\\' + value_name + '\n';
  security_hole(port:port, extra:report);
}
else security_hole(port);
