#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73984);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/19 18:02:19 $");

  script_cve_id("CVE-2014-1812");
  script_bugtraq_id(67275);
  script_osvdb_id(106901);
  script_xref(name:"MSFT", value:"MS14-025");
  script_xref(name:"IAVA", value:"2014-A-0071");

  script_name(english:"MS14-025: Vulnerability in Group Policy Preferences Could Allow Elevation of Privilege (2962486)");
  script_summary(english:"Checks file version of the affected files.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is potentially affected by a privilege
elevation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is potentially affected by a vulnerability in
the way that Active Directory distributes passwords that are
configured using Group Policy preferences. This could allow a remote
attacker to retrieve and decrypt passwords stored with Group Policy
preferences.

The following group policy preferences extensions are affected :

  - Local user and group
   - Mapped drives
   - Services
   - Scheduled tasks (Uplevel)
   - Scheduled tasks (Downlevel)
   - Immediate tasks (Uplevel)
   - Immediate tasks (Downlevel)
   - Data sources

Note that this update does not remove any existing Group Policy
Objects (GPOs). GPOs using the mentioned group policy preferences will
need to be updated to not distribute passwords.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms14-025");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista, 2008, 7,
2008 R2, 8, 2012, 8.1, and 2012 R2.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");

  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS14-025';

kbs = make_list('2928120', '2961899');
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0', win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

vuln = 0;

########## KB2961899 ###########
#  Windows Server 8.1          #
#  Windows Server 2012 R2      #
################################
if (!get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Updates/KB2919355"))
{
  # Windows 8.1 x86 systems only have the gpprefbr.dll updated.
  vuln += hotfix_is_vulnerable(os:"6.3", sp:0, arch:'x86', file:"gpprefbr.dll", version:"6.3.9600.16660", min_version:"6.3.9600.16000", dir:"\system32", bulletin:bulletin, kb:'2961899');

  # Windows 8.1 x64 / Windows 2012 R2
  vuln += hotfix_is_vulnerable(os:"6.3", sp:0, arch:'x64', file:"gppref.dll", version:"6.3.9600.16660", min_version:"6.3.9600.16000", dir:"\system32", bulletin:bulletin, kb:'2961899');
}
########## KB2928120 ###########
#  Windows Vista SP2,          #
#  Windows 7 SP1,              #
#  Windows Server 2008 R2      #
#  Windows Server 8            #
#  Windows Server 8.1          #
#  Windows Server 2012         #
#  Windows Server 2012 R2      #
################################
else
{
  # Windows 8.1 x86 systems only have the gpregistrybrowser.dll updated.
  vuln += hotfix_is_vulnerable(os:"6.3", sp:0, arch:'x86', file:"gpregistrybrowser.dll", version:"6.3.9600.16384", min_version:"6.3.9600.16000", dir:"\system32", bulletin:bulletin, kb:'2928120');

  # Windows 8.1 x64 / Windows 2012 R2
  vuln += hotfix_is_vulnerable(os:"6.3", sp:0, arch:'x64', file:"gppref.dll", version:"6.3.9600.17041", min_version:"6.3.9600.16000", dir:"\system32", bulletin:bulletin, kb:'2928120');
}

# Windows 8 / Windows 2012
vuln += hotfix_is_vulnerable(os:"6.2", sp:0, file:"gppref.dll", version:"6.2.9200.16859", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:'2928120');

vuln += hotfix_is_vulnerable(os:"6.2", sp:0, file:"gppref.dll", version:"6.2.9200.20978", min_version:"6.2.9200.20000", dir:"\system32", bulletin:bulletin, kb:'2928120');

# Windows 7 / Windows 2008 R2
vuln += hotfix_is_vulnerable(os:"6.1", sp:1, file:"gppref.dll", version:"6.1.7601.18399", min_version:"6.1.7600.17000", dir:"\system32", bulletin:bulletin, kb:'2928120');

vuln += hotfix_is_vulnerable(os:"6.1", sp:1, file:"gppref.dll", version:"6.1.7601.22605", min_version:"6.1.7601.22000", dir:"\system32", bulletin:bulletin, kb:'2928120');

# Windows Vista / Windows 2008
vuln += hotfix_is_vulnerable(os:"6.0", sp:2, file:"gppref.dll", version:"6.0.6002.19047", min_version:"6.0.6001.18000", dir:"\system32", bulletin:bulletin, kb:'2928120');

vuln += hotfix_is_vulnerable(os:"6.0", sp:2, file:"gppref.dll", version:"6.0.6002.23339", min_version:"6.0.6002.23000", dir:"\system32", bulletin:bulletin, kb:'2928120');

if (vuln > 0)
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
