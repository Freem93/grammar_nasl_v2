#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55571);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/07/11 14:12:52 $");

  script_cve_id("CVE-2010-3148");
  script_bugtraq_id(42681);
  script_osvdb_id(67546);
  script_xref(name:"EDB-ID", value:"14744");
  script_xref(name:"IAVA", value:"2011-A-0098");
  script_xref(name:"MSFT", value:"MS11-055");
  script_xref(name:"Secunia", value:"45077");

  script_name(english:"MS11-055: Vulnerability in Microsoft Visio Could Allow Remote Code Execution (2560847)");
  script_summary(english:"Checks version of Omfcu.dll");

  script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote Windows host through
Visio.");
  script_set_attribute(attribute:"description", value:
"The remote host contains a version of Microsoft Visio that is
affected by an insecure library loading vulnerability.

A remote attacker could exploit this by tricking a user into opening a
specially crafted Microsoft Visio file, resulting in arbitrary code
execution.");

  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms11-055");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a patch for Visio 2003.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/08/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visio");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, 'Host/patch_management_checks');

  exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");
include("audit.inc");


get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS11-055';
kbs = make_list("2493523");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

installs = get_kb_list_or_exit("SMB/Office/Visio/*/VisioPath");

share = '';
kb = "2493523";
foreach install (keys(installs))
{
  version = install - 'SMB/Office/Visio/' - '/VisioPath';
  if (version =~ '^11\\.0')
  {
    path = installs[install];
    share = hotfix_path2share(path:path);
    if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

    if (hotfix_is_vulnerable(path:path, file:"Visio11\Omfcu.dll", version:"11.0.8332.0", bulletin:bulletin, kb:kb))
    {
      set_kb_item(name:"SMB/Missing/" + bulletin, value:TRUE);
      hotfix_security_hole();
      hotfix_check_fversion_end();
      exit(0);
    }
  }
}
hotfix_check_fversion_end();
audit(AUDIT_HOST_NOT, 'affected');
