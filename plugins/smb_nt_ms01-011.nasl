#
# (C) Tenable Network Security, Inc.
#

# MS01-011 was superceded by MS01-036

include("compat.inc");

if (description)
{
 script_id(10619);
 script_version("$Revision: 1.48 $");
 script_cvs_date("$Date: 2017/05/26 15:15:34 $");

 script_cve_id("CVE-2001-0502");
 script_bugtraq_id(2929);
 script_osvdb_id(515);
 script_xref(name:"MSFT", value:"MS01-011");
 script_xref(name:"MSFT", value:"MS01-036");
 script_xref(name:"MSKB", value:"299687");

 script_name(english:"MS01-011 / MS01-036: LDAP over SSL Arbitrary User Password Modification (287397 / 299687)");
 script_summary(english:"Determines whether the hotfix Q299687 is installed");

 script_set_attribute(attribute:"synopsis", value:
"A bug in Windows 2000 may allow an attacker to change the password of
a third-party user.");
 script_set_attribute(attribute:"description", value:
"The remote version of Windows 2000 contains a bug in its LDAP
implementation that fails to validate the permissions of a user
requesting to change the password of a third-party user.

An attacker may exploit this vulnerability to gain unauthorized access
to the remote host.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms01-011");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms01-036");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Windows 2000.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
 script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2001/02/20");
 script_set_attribute(attribute:"patch_publication_date", value:"2001/02/20");
 script_set_attribute(attribute:"plugin_publication_date", value:"2001/02/21");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2001-2017 Tenable Network Security, Inc.");
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

bulletin = 'MS01-036';
kb = "299687";

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


get_kb_item_or_exit('SMB/Registry/Enumerated');
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp(win2k:3) <= 0) exit(0, "The host is not affected based on its version / service pack.");
if (hotfix_check_domain_controler() <= 0) exit(0);


if (
  hotfix_missing(name:"SP2SPR1") > 0 &&
  hotfix_missing(name:"Q299687") > 0
)
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


