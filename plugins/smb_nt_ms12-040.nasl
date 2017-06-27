#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(59458);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/07/01 20:31:47 $");

  script_cve_id("CVE-2012-1857");
  script_bugtraq_id(53863);
  script_osvdb_id(82853);
  script_xref(name:"MSFT", value:"MS12-040");
  script_xref(name:"IAVB", value:"2012-B-0059");

  script_name(english:"MS12-040: Vulnerability in Microsoft Dynamics AX Enterprise Portal Could Allow Elevation of Privilege (2709100)");
  script_summary(english:"Looks for MS12-040 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A web application on the remote host has a cross-site scripting
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Microsoft Dynamics AX Enterprise Portal on the remote
host has an unspecified cross-site scripting vulnerability.   An
attacker could exploit this by tricking a user into making a malicious
request, resulting in arbitrary script code execution.

This plugin checks if the system is missing KB2711239."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS12-040");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Dynamics AX 2012
Enterprise Portal."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:dynamics_ax");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "microsoft_dynamics_ax_installed.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");
include("audit.inc");

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');
bulletin = 'MS12-040';
kbs = make_list('2711239');

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit('SMB/microsoft_dynamics_ax/installed_component/EnterprisePortal');  # ensure the EP component is installed
path = get_kb_item_or_exit('SMB/microsoft_dynamics_ax/path');
ver = get_kb_item_or_exit('SMB/microsoft_dynamics_ax/ver');

# 6.0 is Dynamics AX 2012
if (ver != '6.0') audit(AUDIT_INST_VER_NOT_VULN, 'Dynamics AX', ver);
if (!is_accessible_share()) exit(1, 'is_accessible_share() failed.');

vuln = 0;
vuln += hotfix_is_vulnerable(file:"Microsoft.dynamics.ax.managedinterop.dll", version:"6.0.1108.748", min_version:"6.0.0.0", path:path + "\Server\MicrosoftDynamicsAX\bin", bulletin:bulletin, kb:'2711239');

if (vuln > 0)
{
  set_kb_item(name:'www/0/XSS', value:TRUE);
  set_kb_item(name:'SMB/Missing/' + bulletin, value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  exit(0, 'The host is not affected.');
}
