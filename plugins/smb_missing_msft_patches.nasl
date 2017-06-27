#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if ( NASL_LEVEL < 3000 ) exit(0);

if (description)
{
  script_id(38153);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2017/05/25 21:43:15 $");

  script_name(english: "Microsoft Windows Summary of Missing Patches");
  script_summary(english:"Displays the list of missing MSFT patches.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing several Microsoft security patches.");
  script_set_attribute(attribute:"description", value:
"This plugin summarizes updates for Microsoft Security Bulletins or
Knowledge Base (KB) security updates that have not been installed on
the remote Windows host based on the results of either a credentialed
check using the supplied credentials or a check done using a supported
third-party patch management tool.

Review the summary and apply any missing updates in order to be up to
date.");
  script_set_attribute(attribute:"solution", value:
"Run Windows Update on the remote host or use a patch management
solution.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_END);
  script_family(english:"Windows : Microsoft Bulletins");
  script_copyright(english:"This script is Copyright (C) 2009-2017 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("misc_func.inc");

if (!get_kb_item("SMB/MS_Bulletin_Checks/Possible"))
{
  os = get_kb_item("Host/OS");
  if (!isnull(os) && "indows" >< os) exit(0, "Nessus is not able to test for Microsoft's patch bulletins.");
  else exit(0, "The host does not appear to be running Windows.");
}

list = get_kb_list("SMB/Missing/*");
if ( isnull(list) ) exit(0, "No missing patches were found in the KB for this host.");

report = 'The patches for the following bulletins or KBs are missing on the remote host :\n\n';
foreach patch (sort(keys(list))) 
{
  patch -= "SMB/Missing/";
  
  if(patch =~ "MS[0-9]{2}-[0-9]{2}$")
  {

    n = query_scratchpad("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'SMB_HF'");
    if (!isnull(n) && !isnull(n[0]))
    {
      kbs = query_scratchpad("SELECT bulletin,kb FROM SMB_HF WHERE bulletin = ?", patch);
      foreach entry (kbs)
      {
        report += ' - KB' + entry["kb"] + ' ( https://support.microsoft.com/en-us/help/' + entry["kb"] + ' )\n';
      }
    }
  }
  else
    report += ' - ' + patch + ' ( http://technet.microsoft.com/en-us/security/bulletin/' + tolower(patch) + ' )\n';
}

port = get_kb_item("SMB/transport");
if (isnull(port))
  port = 445;

security_note(port:port, extra:report);
