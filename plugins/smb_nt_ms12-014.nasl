#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(57948);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/04/23 21:35:41 $");

  script_cve_id("CVE-2010-3138");
  script_bugtraq_id(42730);
  script_osvdb_id(67551);
  script_xref(name:"EDB-ID", value:"14765");
  script_xref(name:"EDB-ID", value:"14788");
  script_xref(name:"MSFT", value:"MS12-014");
  script_xref(name:"Secunia", value:"41114");

  script_name(english:"MS12-014: Vulnerability in Indeo Codec Could Allow Remote Code Execution (2661637)");
  script_summary(english:"Checks version of Iacenc.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:
"Arbitrary code can be executed on the remote Windows host through the
Indeo codec."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Windows XP host contains a version of the Indeo codec that
is affected by an insecure library loading vulnerability.

A remote attacker could exploit this by tricking a user into opening a
legitimate file (e.g., an .avi file) located in the same directory as
a maliciously crafted dynamic link library (DLL) file, resulting in
arbitrary code execution."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.zeroscience.mk/en/vulnerabilities/ZSL-2010-4956.php");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms12-014");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a patch for Windows XP.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/08/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows_xp");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS12-014';
kb = '2661637';
kbs = make_list(kb);

if (get_kb_item('Host/patch_management_checks'))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


# The advisory says only XP SP3 is vulnerable
win_ver = get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);
sp = get_kb_item_or_exit("SMB/CSDVersion");
sp = ereg_replace(pattern:".*Service Pack ([0-9]).*", string:sp, replace:"\1");
sp = int(sp);
if (win_ver != '5.1' || sp != 3)
  exit(0, 'Only Windows XP SP3 is affected.');

if (!is_accessible_share())
  exit(1, 'is_accessible_share() failed.');

file = "\system32\Iacenc.dll";
r = hotfix_check_fversion(file:file, version:'1.0.0.0', bulletin:bulletin, kb:kb);
if (r == HCF_OLDER || r == HCF_NOENT)  # file out of date or FNF
{
  if (r == HCF_NOENT)
  {
    path = hotfix_get_systemroot() + file;
    info = '\nThe following file was not found :\n\n' + path + '\n\nThis indicates KB' + kb + ' is missing.\n';
    hotfix_add_report(info);
  }

  set_kb_item(name:'SMB/Missing/' + bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  exit(0, 'The host is not affected.');
}

