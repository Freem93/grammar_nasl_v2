#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86849);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/07/06 19:24:46 $");

  script_cve_id("CVE-2015-6061");
  script_bugtraq_id(77477);
  script_osvdb_id(130061);
  script_xref(name:"MSFT", value:"MS15-123");
  script_xref(name:"IAVA", value:"2015-A-0279");

  script_name(english:"MS15-123: Security Update for Skype for Business and Microsoft Lync to Address Information Disclosure (3105872)");
  script_summary(english:"Checks the file versions.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is affected by a cross-site scripting (XSS)
vulnerability in Skype for Business and Lync clients due to improper
sanitization of message content before returning it to the user. A
remote attacker can exploit this, using specially crafted JavaScript,
to execute arbitrary script and HTML in the user's context, resulting
in the possible disclosure of sensitive information or other actions.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/en-us/library/ms15-123.aspx");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Lync 2010, Lync 2010
Attendee, Lync 2013, Lync Basic 2013, Skype for Business 2016, Skype
for Business Basic 2016, and Lync Room System.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/11/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:lync");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:lync_basic");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:lync_room_system");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:skype_for_business");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl", "office_installed.nasl", "microsoft_lync_server_installed.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");
include("install_func.inc");

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

global_var bulletin, vuln, arch;

arch = get_kb_item_or_exit('SMB/ARCH');
vuln = 0;
bulletin = 'MS15-123';

kbs = make_list(
  '3085634', # Skype For Biz 2016
  '3101496', # Lync 2013 (Skype for Biz)
  '3096735', # Lync 2010
  '3096736', # Lync 2010 Attendee (User Level)
  '3096738'  # Lync 2010 Attendee (Admin Level)
);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);
if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0', win81:'0', win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(exit_on_fail:TRUE, as_share:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

# Lync checks
function perform_lync_checks()
{
  local_var lync_count, lync_installs, lync_install;

  lync_count = get_install_count(app_name:"Microsoft Lync");

  # Nothing to do
  if (int(lync_count) <= 0)
    return;

  lync_installs = get_installs(app_name:"Microsoft Lync");
  foreach lync_install (lync_installs[1])
  {
    if (lync_install["version"] =~ "^4\.0\." && "Server" >!< lync_install["Product"])
    {
      # Lync 2010
      if ("Attendee" >!< lync_install["Product"])
      {
        if (hotfix_check_fversion(file:"communicator.exe", version:"4.0.7577.4484", min_version:"4.0.0.0", path:lync_install["path"], bulletin:bulletin, kb:"3096735", product:"Microsoft Lync 2010") == HCF_OLDER)
          vuln++;
      }
      # Lync 2010 Attendee
      else if ("Attendee" >< lync_install["Product"])
      {
        if ("user level" >< tolower(lync_install["Product"])) # User
        {
          if (hotfix_check_fversion(file:"MeetingJoinAxAOC.DLL", version:"4.0.7577.4484", min_version:"4.0.0.0", path:lync_install["path"], bulletin:bulletin, kb:"3096736", product:lync_install["Product"]) == HCF_OLDER)
            vuln++;
        }
        else # Admin
        {
          if (hotfix_check_fversion(file:"MeetingJoinAxAOC.DLL", version:"4.0.7577.4484", min_version:"4.0.0.0", path:lync_install["path"], bulletin:bulletin, kb:"3096738", product:lync_install["Product"]) == HCF_OLDER)
            vuln++;
        }
      }
    }
    # Lync 2013
    else if (lync_install["version"] =~ "^15\.0\." && "Server" >!< lync_install["Product"])
    {
      if (hotfix_check_fversion(file:"Lync.exe", version:"15.0.4771.1001", min_version:"15.0.4569.1503", path:lync_install["path"], bulletin:bulletin, kb:"3101496", product:"Microsoft Lync 2013 (Skype for Business)") == HCF_OLDER)
        vuln++;
    }
    # Skype for Business 2016
    else if (lync_install["version"] =~ "^16\.0\." && "Server" >!< lync_install["Product"])
    {
      if (hotfix_check_fversion(file:"Lync.exe", version:"16.0.4300.1001", channel:"MSI", channel_product:"Lync", path:lync_install["path"], bulletin:bulletin, kb:"3085634", product:"Skype for Business 2016") == HCF_OLDER)
        vuln++;
      if (hotfix_check_fversion(file:"Lync.exe", version:"16.0.6001.1038", channel:"Current", channel_product:"Lync", path:lync_install["path"], bulletin:bulletin, kb:"3085634", product:"Skype for Business 2016") == HCF_OLDER)
        vuln++;
    }
  }
}

perform_lync_checks();

if(vuln)
{
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
