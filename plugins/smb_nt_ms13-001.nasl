#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63419);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/04/23 21:44:06 $");

  script_cve_id("CVE-2013-0011");
  script_bugtraq_id(57142);
  script_osvdb_id(88956);
  script_xref(name:"MSFT", value:"MS13-001");

  script_name(english:"MS13-001: Vulnerabilities in Windows Print Spooler Components Could Allow Remote Code Execution (2769369)");
  script_summary(english:"Checks version of win32spl.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host is potentially affected by a code execution
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Windows host is potentially affected by a vulnerability that
could allow remote code execution if a print server received a specially
crafted print job.  Firewall best practices and standard default
firewall configurations can help protect networks from attacks that
originate outside the enterprise perimeter.  Best practices recommend
that systems connected directly to the Internet have a minimal number of
ports exposed."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms13-001");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Windows 7, and 2008 R2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, 'Host/patch_management_checks');

  exit(0);
}

include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = "MS13-001";
kb = "2769369";

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(win7:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows Embedded" >< productname) exit(0, "The host is running "+productname+" and hence is not affected.");

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (hotfix_check_server_core() == 1)
{
  #check to see if Printing-ServerCore-Role is enabled
  registry_init();
  hcf_init = TRUE;
  hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
  dval = get_registry_value(handle:hklm, item:"SOFTWARE\Policies\Microsoft\Windows NT\Printers\RegisterSpoolerRemoteRpcEndPoint");
  RegCloseKey(handle:hklm);
  close_registry(close:FALSE);

  # if dval == 0, then the system is not vulnerable
  if (!dval) audit(AUDIT_HOST_NOT, 'affected');
}

if (
  # Windows 7 and Windows Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:0, file:"win32spl.dll", version:"6.1.7600.17162", min_version:"6.1.7600.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:0, file:"win32spl.dll", version:"6.1.7600.21365", min_version:"6.1.7600.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"win32spl.dll", version:"6.1.7601.17994", min_version:"6.1.7601.17000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"win32spl.dll", version:"6.1.7601.22156", min_version:"6.1.7601.21000", dir:"\system32", bulletin:bulletin, kb:kb)
)
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
