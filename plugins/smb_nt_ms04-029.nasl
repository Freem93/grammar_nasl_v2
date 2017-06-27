#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(15467);
 script_version("$Revision: 1.27 $");
 script_cvs_date("$Date: 2015/04/23 21:04:49 $");

 script_cve_id("CVE-2004-0569");
 script_bugtraq_id(11380);
 script_osvdb_id(10686);
 script_xref(name:"MSFT", value:"MS04-029");

 script_name(english:"MS04-029: Vulnerability in RPC Runtime Library Could Allow Information Disclosure and Denial of Service (873350)");
 script_summary(english:"Determines if hotfix 873350 has been installed");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to crash the remote web server or retrieve sensitive
information.");
 script_set_attribute(attribute:"description", value:
"The remote Windows operating system contains a bug in RPC Runtime
Library.

RPC is a protocol used by Windows to provide an inter-process
communication mechanism that allows a program running on one system to
access services on another one.

A bug affecting the implementation of this protocol could allow an
attacker to cause it to crash, thus resulting in a crash of the whole
operating system, or to disclose random parts of the memory of the
remote host.

An attacker could exploit this flaw to obtain sensitive information
about the remote host, by forcing it to disclose portions of memory
containing passwords, or to cause it to crash repeatedly, thus causing a
denial of service for legitimate users.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms04-029");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a patch for Windows NT.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/10/12");
 script_set_attribute(attribute:"patch_publication_date", value:"2004/10/12");
 script_set_attribute(attribute:"plugin_publication_date", value:"2004/10/13");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
 script_require_keys("SMB/MS_Bulletin_Checks/Possible");
 script_require_ports(139, 445, 'Host/patch_management_checks');
 exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS04-029';
kb = '873350';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(nt:'6') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (hotfix_is_vulnerable(os:"4.0", file:"Rpcrt4.dll", version:"4.0.1381.7299", dir:"\system32", bulletin:bulletin, kb:kb))
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
