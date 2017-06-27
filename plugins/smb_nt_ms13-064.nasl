#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69329);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/04/23 21:44:06 $");

  script_cve_id("CVE-2013-3182");
  script_bugtraq_id(61685);
  script_osvdb_id(96195);
  script_xref(name:"MSFT", value:"MS13-064");
  script_xref(name:"IAVB", value:"2013-B-0089");

  script_name(english:"MS13-064: Vulnerability in Windows NAT Driver Could Allow Denial of Service (2849568)");
  script_summary(english:"Checks version of the Windows NAT Driver Winnat.sys file.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The version of Windows NAT Driver installed on the remote host is
affected by a denial of service vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Windows host is running a version of the Windows NAT Driver
that is affected by a denial of service (DoS) vulnerability.  An
attacker could cause the host to stop responding until restarted by
sending a specially crafted ICMP packet to the system."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS13-064");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a patch for Windows Server 2012.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/08/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
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

bulletin = 'MS13-064';
kb = "2849568";

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
win_ver = get_kb_item_or_exit('SMB/WindowsVersion');

if (hotfix_check_sp_range(win8:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ( ("Windows Embedded" >< productname) || ("Windows 8" >< productname) ) exit(0, "The host is running "+productname+" and is, therefore, not affected.");

#  Does NOT affect server core
if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

vuln = 0;

################################
#  Server 2012                 #
################################
if (
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"Winnat.sys", version: "6.2.9200.16654", min_version:"6.2.9200.16000", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"Winnat.sys", version: "6.2.9200.20762", min_version:"6.2.9200.20000", dir:"\system32\drivers", bulletin:bulletin, kb:kb)
) vuln++;

if (vuln > 0)
{
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
