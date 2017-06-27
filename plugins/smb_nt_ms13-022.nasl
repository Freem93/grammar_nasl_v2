#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(65211);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/12/09 21:04:54 $");

  script_cve_id("CVE-2013-0074");
  script_bugtraq_id(58327);
  script_osvdb_id(91147);
  script_xref(name:"MSFT", value:"MS13-022");

  script_name(english:"MS13-022: Vulnerability in Microsoft Silverlight Could Allow Remote Code Execution (2814124)");
  script_summary(english:"Checks version of Silverlight.exe");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A browser enhancement on the remote Windows host could allow arbitrary
code execution."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Microsoft Silverlight installed on the remote host
reportedly incorrectly checks a memory pointer when rendering an HTML
object, which could allow a specially crafted application to access
memory in an unsafe fashion.

If an attacker could trick a user on the affected system into visiting a
website hosting a malicious Silverlight application, the attacker could
leverage this vulnerability to execute arbitrary code on the affected
system, subject to the user's privileges."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms13-022");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Silverlight 5.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'MS13-022 Microsoft Silverlight ScriptObject Unsafe Memory Access');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:silverlight");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "silverlight_detect.nasl", "ms_bulletin_checks_possible.nasl");
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

bulletin = 'MS13-022';
kb = "2814124";

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");

# Silverlight 5.x
ver = get_kb_item("SMB/Silverlight/Version");
fix = '5.1.20125.0';

if (!isnull(ver) && ver =~ '^5\\.' && ver_compare(ver:ver, fix:fix) == -1)
{
  path = get_kb_item("SMB/Silverlight/Path");
  report +=
    '\n  Product           : Microsoft Silverlight' +
    '\n  Path              : ' + path +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix + '\n';
  hotfix_add_report(report, bulletin:bulletin, kb:kb);

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
