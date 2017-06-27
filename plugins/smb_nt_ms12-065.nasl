#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62460);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/12/09 21:04:54 $");

  script_cve_id("CVE-2012-2550");
  script_bugtraq_id(55796);
  script_osvdb_id(86056);
  script_xref(name:"MSFT", value:"MS12-065");

  script_name(english:"MS12-065: Vulnerability in Microsoft Works Could Allow Remote Code Execution (2754670)");
  script_summary(english:"Checks version of wkwpqd.dll");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host could allow arbitrary code execution.");
  script_set_attribute( attribute:"description", value:
"The remote host is running a version of Microsoft Works for Windows
that is affected by a heap overflow vulnerability.  If an attacker can
trick a user on the affected host into opening a specially crafted Works
file, the attacker may be able to leverage this issue to run arbitrary
code on the host subject to the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms12-065");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a patch for Microsoft Works 9.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:works");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "office_installed.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, 'Host/patch_management_checks');

  exit(0);
}

include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = "MS12-065";
kb = '2754670';
kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

if (!hotfix_check_works_installed()) audit(AUDIT_NOT_INST, "Microsoft Works");

prgfiles = hotfix_get_programfilesdir();
if (!prgfiles) exit(1, "Error getting Program Files directory.");

share = hotfix_path2share(path:prgfiles);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

path = prgfiles + "\Microsoft Works";

# Works 9.
if (hotfix_check_fversion(file:"wkwpqd.dll", version:"9.12.521.0", min_version:"9.0.0.0", path:path, bulletin:bulletin, kb:kb) == HCF_OLDER)
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_hole();

  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, "affected");
}
