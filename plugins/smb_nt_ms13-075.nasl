#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(69927);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/01/28 22:37:18 $");

  script_cve_id("CVE-2013-3859");
  script_bugtraq_id(62181);
  script_osvdb_id(97109);
  script_xref(name:"MSFT", value:"MS13-075");
  script_xref(name:"IAVB", value:"2013-B-0102");

  script_name(english:"MS13-075: Vulnerability in Microsoft Office IME (Chinese) Could Allow Elevation of Privilege (2878687)");
  script_summary(english:"Checks version of Imsctip.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The version of Microsoft Office installed on the remote Windows host
has a privilege escalation vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Microsoft Office Input Method Editor (Chinese) installed
on the remote host has a privilege escalation vulnerability.  A local
attacker could exploit this by utilizing the MSPY IME toolbar in an
unspecified manner, resulting in arbitrary code execution in kernel
mode."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms13-075");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Pinyin IME 2010.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:pinyin_ime");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl", "office_installed.nasl");
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

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS13-075';
kbs = make_list('2687413');

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

# Make sure the Correct version of Office is installed
office_product_codes = make_list(
  '90140000-0028-0411-0000-0000000FF1CE', # Japan
  '90140000-0028-0412-0000-0000000FF1CE', # Korean
  '90140000-0028-0804-0000-0000000FF1CE', # Chinese
  '90140000-0028-0404-0000-0000000FF1CE'  # Taiwan
);
affectedproduct = FALSE;
registry_init();
hcf_init = TRUE;

hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
for (i=0; i < max_index(office_product_codes); i++)
{
  key = "SOFTWARE\Microsoft\Office\14.0\Common\InstalledPackages" + '\\' + office_product_codes[i]+ '\\';
  res = get_registry_value(handle:hklm, item:key);
  if ('Microsoft Office IME' >< res) affectedproduct = TRUE;
}
RegCloseKey(handle:hklm);
close_registry(close:FALSE);

if (!affectedproduct)
{
  close_registry();
  exit(0, 'The host is not affected based on the installed variant of Microsoft Office.');
}

office_sp = get_kb_item("SMB/Office/2010/SP");
if (isnull(office_sp))
{
  close_registry();
  exit(0, 'The \'SMB/Office/2010/SP\' KB item is missing.');
}

if (int(office_sp) < 1) exit(0, 'The version of Office 2010 is earlier than Service Pack 1.');

common = hotfix_get_officecommonfilesdir(officever:"14.0");
if (!common)
{
  close_registry();
  exit(1, 'hotfix_get_officecommonfilesdir() failed.');
}

share = hotfix_path2share(path:common);
ime_path = common + "\Microsoft Shared\IME14\IMESC";      # Pinyin IME bundled with Office 2010 Chinese

if (!is_accessible_share(share:share))
{
  close_registry();
  exit(1, 'Unable to connect to ' + share + ' share.');
}

# it's possible that both KBs need to be installed on the same system
res = hotfix_is_vulnerable(path:ime_path, file:"Imsctip.dll", version:"14.0.7104.5000", min_version:"14.0.0.0", bulletin:bulletin, kb:"2687413");

if (res)
{
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  exit(0, 'The host is not affected.');
}
