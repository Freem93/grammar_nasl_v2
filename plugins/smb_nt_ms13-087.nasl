#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(70339);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/01/28 22:37:18 $");

  script_cve_id("CVE-2013-3896");
  script_bugtraq_id(62793);
  script_osvdb_id(98223);
  script_xref(name:"MSFT", value:"MS13-087");

  script_name(english:"MS13-087: Vulnerability in Silverlight Could Allow Information Disclosure (2890788)");
  script_summary(english:"Checks version of Silverlight.exe");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A browser enhancement on the remote Windows host is affected by an
information disclosure vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Microsoft Silverlight installed on the remote host
reportedly is affected by an information disclosure vulnerability due to
its failure to properly handle certain objects in memory.

If an attacker could trick a user on the affected system into visiting a
website hosting a malicious Silverlight application, the attacker could
leverage this vulnerability to disclose information from the affected
system, subject to the user's privileges."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms13-087");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Silverlight 5.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'MS13-022 Microsoft Silverlight ScriptObject Unsafe Memory Access');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
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

bulletin = 'MS13-087';
kb = "2890788";

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");

# Silverlight 5.x
ver = get_kb_item("SMB/Silverlight/Version");
if (isnull(ver)) audit(AUDIT_NOT_INST, "Silverlight");
if (ver !~ "^5\.") audit(AUDIT_NOT_INST, "Silverlight 5");

fix = "5.1.20913.0";
if (ver_compare(ver:ver, fix:fix) == -1)
{
  path = get_kb_item("SMB/Silverlight/Path");
  if (isnull(path)) path = 'n/a';

  report +=
    '\n  Path              : ' + path +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix +
    '\n';
  hotfix_add_report(report, bulletin:bulletin, kb:kb);

  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
