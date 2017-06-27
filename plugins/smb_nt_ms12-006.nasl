#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57474);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2015/10/07 18:00:12 $");

  script_cve_id("CVE-2011-3389");
  script_bugtraq_id(49778);
  script_osvdb_id(74829);
  script_xref(name:"CERT", value:"864643");
  script_xref(name:"MSFT", value:"MS12-006");
  script_xref(name:"IAVB", value:"2012-B-0006");

  script_name(english:"MS12-006: Vulnerability in SSL/TLS Could Allow Information Disclosure (2643584)");
  script_summary(english:"Checks version of schannel.dll and Winhttp.dll");

  script_set_attribute(attribute:"synopsis", value:
"It may be possibe to obtain sensitive information from the remote
Windows host using the Secure Channel security package.");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by an information disclosure
vulnerability, known as BEAST, in the SSL 3.0 and TLS 1.0 protocols
due to a flaw in the way the initialization vector (IV) is selected
when operating in cipher-block chaining (CBC) modes. A
man-in-the-middle attacker can exploit this to obtain plaintext HTTP
header data, by using a blockwise chosen-boundary attack (BCBA) on an
HTTPS session, in conjunction with JavaScript code that uses the HTML5
WebSocket API, the Java URLConnection API, or the Silverlight
WebClient API.

TLS 1.1, TLS 1.2, and all cipher suites that do not use CBC mode are
not affected.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms12-006");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2011/09/23/chromeandbeast.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/~bodo/tls-cbc.txt");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for XP, 2003, Vista, 2008, 7,
and 2008 R2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/09/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
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

bulletin = 'MS12-006';
kbs = make_list('2585542', '2638806');
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit('SMB/Registry/Enumerated');
winver = get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(xp:'3', win2003:'2', vista:'2', win7:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

vuln = 0;
if (winver == '5.2')
{
  rootfile = hotfix_get_systemroot();
  if (!rootfile)  exit(1, "Can't get the system root.");

  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:rootfile);
  path  = ereg_replace(pattern:"^[A-Za-z](.*)", replace:"\1", string:rootfile);

  login  = kb_smb_login();
  pass   = kb_smb_password();
  domain = kb_smb_domain();
  port   = kb_smb_transport();

  if(! smb_session_init(timeout: get_read_timeout() + 10)) audit(AUDIT_FN_FAIL, "smb_session_init");

  hcf_init = TRUE;

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    audit(AUDIT_SHARE_FAIL, share);
  }

  winsxs = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\WinSxS", string:rootfile);
  files = list_dir(basedir:winsxs, level:0, dir_pat:"WinHTTP", file_pat:"^winhttp\.dll$", max_recurse:1);

  vuln += hotfix_check_winsxs(os:'5.2', sp:2, files:files, versions:make_list('5.2.3790.4929'), max_versions:make_list('5.2.3790.9999'), bulletin:bulletin, kb:'2638806');
}

kb = '2585542';
if (!is_accessible_share()) exit(1, "is_accessible_share() failed.");
if (
  # Windows 7 / Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1,             file:"Schannel.dll", version:"6.1.7601.21861", min_version:"6.1.7601.21000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1,             file:"Schannel.dll", version:"6.1.7601.17725", min_version:"6.1.7601.17000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:0,             file:"Schannel.dll", version:"6.1.7600.21092", min_version:"6.1.7600.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:0,             file:"Schannel.dll", version:"6.1.7600.16915", min_version:"6.1.7600.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Vista / Windows Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:2,             file:"Schannel.dll", version:"6.0.6002.22742", min_version:"6.0.6002.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2,             file:"Schannel.dll", version:"6.0.6002.18541", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 2003
  hotfix_is_vulnerable(os:"5.2", sp:2,             file:"Schannel.dll", version:"5.2.3790.4935", dir:"\System32", bulletin:bulletin, kb:kb) ||

  # Windows XP
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Schannel.dll", version:"5.1.2600.6175", dir:"\System32", bulletin:bulletin, kb:kb)
)
{
  vuln++;
  hotfix_check_fversion_end();
}
hotfix_check_fversion_end();

if (vuln)
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_warning();

  exit(0);
}
else audit(AUDIT_HOST_NOT, 'affected');
