#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(10485);
  script_version("$Revision: 1.42 $");
  script_cvs_date("$Date: 2017/05/26 15:15:34 $");

  script_cve_id("CVE-2000-0737");
  script_bugtraq_id(1535);
  script_osvdb_id(384);
  script_xref(name:"CERT", value:"31607");
  script_xref(name:"MSFT", value:"MS00-053");
  script_xref(name:"MSKB", value:"269523");

  script_name(english:"MS00-053: Service Control Manager Named Pipe Impersonation patch (269523)");
  script_summary(english:"Determines whether the hotfix Q269523 is installed");

  script_set_attribute(attribute:"synopsis", value:"The remote host is prone to a privilege escalation attack.");
  script_set_attribute(attribute:"description", value:
"The hotfix for the 'Service Control Manager Named Pipe Impersonation'
problem has not been applied.

This vulnerability allows a malicious user, who has the right to log on
this host locally, to gain additional privileges.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms00-053");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patches from MS00-053 or apply the latest
Windows service pack.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2000/08/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2000/08/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2000/08/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2000-2017 Tenable Network Security, Inc.");
  script_family(english:"Windows : Microsoft Bulletins");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}


include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS00-053';
kb = "269523";

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


get_kb_item_or_exit('SMB/Registry/Enumerated');
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp(win2k:2) <= 0) exit(0, "The host is not affected based on its version / service pack.");


if (hotfix_missing(name:"Q269523") > 0)
{
  if (
    defined_func("report_xml_tag") &&
    !isnull(bulletin) &&
    !isnull(kb)
  ) report_xml_tag(tag:bulletin, value:kb);

  hotfix_security_hole();
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  exit(0);
}
else exit(0, "The host is not affected.");


