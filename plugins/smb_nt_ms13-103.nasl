#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71318);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/01/28 22:37:18 $");

  script_cve_id("CVE-2013-5042");
  script_bugtraq_id(64093);
  script_osvdb_id(100770);
  script_xref(name:"MSFT", value:"MS13-103");
  script_xref(name:"IAVA", value:"2013-A-0224");

  script_name(english:"MS13-103: Vulnerability in ASP.NET SignalR Could Allow Elevation of Privilege (2905244)");
  script_summary(english:"Checks version of Microsoft.TeamFoundation.Chat.Server.dll and Microsoft.AspNet.SignalR.Core.dll");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by a cross-site
scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of ASP.NET SignalR that is
affected by a cross-site scripting vulnerability that results in
privilege escalation. An attacker who successfully exploited this
vulnerability could take any action that the targeted user could take
on the site.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms13-103");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Visual Studio Team
Foundation Server 2013 and ASP.NET SignalR.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/12/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:asp.net_signalr");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_studio_team_foundation_server");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "microsoft_team_foundation_server_installed.nasl", "ms_bulletin_checks_possible.nasl", "smb_enum_shares.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

# ##########################################################
#
# Includes
#
# ##########################################################

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("install_func.inc");
include("misc_func.inc");

# ##########################################################
#
# General Checks and Variables
#
# ##########################################################

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = "MS13-103";
kbs = make_list(2903566, 2903919);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

vuln = 0;

# Get path information for Windows.
windir = hotfix_get_systemroot();
if (isnull(windir)) exit(1, "Failed to determine the location of %windir%.");

# ##########################################################
#
# Microsoft Team Foundation Server 2013
#
# ##########################################################

appname = 'Microsoft Team Foundation Server';
kb = "2903566";

installs = get_installs(app_name:appname, exit_if_not_found:FALSE);
if (installs[0] == IF_OK)
{
  foreach install (installs[1])
  {
    path = install['path'];
    version = install['version'];

    if (version =~ "^12\.0\.") # 2013
    {
      dll = hotfix_append_path(path:path, value:"Application Tier\Web Services\bin\Microsoft.TeamFoundation.Chat.Server.dll");
      if (hotfix_check_fversion(
          file:"Microsoft.TeamFoundation.Chat.Server.dll",
          version:"12.0.21106.0",
          path:hotfix_append_path(path:path, value:"Application Tier\Web Services\bin"),
          bulletin:bulletin,
          kb:kb,
          product:appname) == HCF_OLDER
        ) vuln++;
    }
  }
}

# ##########################################################
#
# ASP.NET SignalR
#
# ##########################################################

appname = 'ASP.NET SignalR';
kb = "2903919";
file = "Microsoft.AspNet.SignalR.Core.dll";

if (
  hotfix_check_fversion(
    file:"Microsoft.AspNet.SignalR.Core.dll",
    version:"1.1.21022.0",
    min_version:"1.1.0.0",
    path:hotfix_append_path(path:windir, value:"Microsoft.NET\assembly\GAC_MSIL\Microsoft.AspNet.SignalR.Core\v4.0_1.1.0.0__31bf3856ad364e35"),
    bulletin:bulletin,
    kb:kb,
    product:appname + ' 1.1.x') == HCF_OLDER
  ) vuln++;

if (hotfix_check_fversion(
    file:"Microsoft.AspNet.SignalR.Core.dll",
    version:"2.0.21023.5",
    min_version:"2.0.0.0",
    path:hotfix_append_path(path:windir, value:"Microsoft.NET\assembly\GAC_MSIL\Microsoft.AspNet.SignalR.Core\v4.0_2.0.0.0__31bf3856ad364e35"),
    bulletin:bulletin,
    kb:kb,
    product:appname + ' 2.0.x') == HCF_OLDER
  ) vuln++;


# ##########################################################
#
# Close up and report
#
# ##########################################################
if (vuln)
{
  set_kb_item(name:"www/0/XSS", value:TRUE);

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
