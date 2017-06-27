#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10615);
 script_version("$Revision: 1.44 $");
 script_cvs_date("$Date: 2017/05/26 15:15:34 $");

 script_cve_id("CVE-2001-0017");
 script_bugtraq_id(2368);
 script_osvdb_id(511);
 script_xref(name:"MSFT", value:"MS01-009");
 script_xref(name:"MSKB", value:"283001");

 script_name(english:"MS01-009: Malformed PPTP Packet Stream Remote DoS (283001)");
 script_summary(english:"Determines whether the hotfix Q283001 is installed");

 script_set_attribute(attribute:"synopsis", value:
"A flaw in the remote PPTP implementation could allow an attacker to
cause a denial of service.");
 script_set_attribute(attribute:"description", value:
"The hotfix for the 'Malformed PPTP Packet Stream' problem has not
been applied.  This hotfix corrects a memory leak in Windows NT PPTP
implementation that could cause it to use all the resources of the
remote host.

An attacker could use this flaw by sending malformed PPTP packets to the
remote host until no more memory is available.  This would result in a
denial of service of the remote service or the whole system.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms01-009");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Windows NT 4.0.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
 script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2001/02/13");
 script_set_attribute(attribute:"patch_publication_date", value:"2001/02/13");
 script_set_attribute(attribute:"plugin_publication_date", value:"2001/02/15");

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

bulletin = 'MS01-009';
kb = "283001";

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);


get_kb_item_or_exit('SMB/Registry/Enumerated');
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp(nt:7) <= 0) exit(0, "The host is not affected based on its version / service pack.");


if (
  hotfix_missing(name:"Q299444") > 0 &&
  hotfix_missing(name:"Q283001") > 0
)
{
  if (
    defined_func("report_xml_tag") &&
    !isnull(bulletin) &&
    !isnull(kb)
  ) report_xml_tag(tag:bulletin, value:kb);

  hotfix_security_warning();
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  exit(0);
}
else exit(0, "The host is not affected.");


