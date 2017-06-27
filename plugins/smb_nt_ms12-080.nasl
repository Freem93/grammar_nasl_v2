#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63227);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/07/01 20:31:47 $");

  script_cve_id("CVE-2012-3214", "CVE-2012-3217", "CVE-2012-4791");
  script_bugtraq_id(55977, 55993, 56836);
  script_osvdb_id(86389, 86392, 88314);
  script_xref(name:"MSFT", value:"MS12-080");

  script_name(english:"MS12-080: Vulnerabilities in Microsoft Exchange Server Could Allow Remote Code Execution (2784126)");
  script_summary(english:"Checks version of transcodingservice.exe");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote mail server has multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Microsoft Exchange installed on the remote host has the
following vulnerabilities :

  - Multiple code execution vulnerabilities in the Oracle Outside In
    libraries, used by the WebReady Document Viewing feature of
    Outlook Web App (OWA).  An attacker could exploit this by
    sending a malicious email attachment to a user who views it in
    OWA, resulting in arbitrary code execution as LocalService.
    (CVE-2012-3214, CVE-2012-3217)

  - A denial of service caused by Exchange improperly handling
    RSS feeds.  An attacker with a valid email account on the
    Exchange server could create a specially crafted RSS feed,
    which could cause the system to become unresponsive and
    result in data corruption. (CVE-2012-4791)"
  );
  # http://www.oracle.com/technetwork/topics/security/cpuoct2012-1515893.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1cef09be");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms12-080");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Exchange 2007 and 2010.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/12/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:exchange_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS12-080';
kbs = make_list('2746157', '2787763', '2785908');

if (get_kb_item('Host/patch_management_checks'))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");

version = get_kb_item_or_exit('SMB/Exchange/Version', exit_code:1);
if (version != 80 && version != 140)
  audit(AUDIT_INST_VER_NOT_VULN, 'Exchange', version);

sp = get_kb_item_or_exit('SMB/Exchange/SP', exit_code:1);
if (version == 80)
{
  if (sp == 3)
  {
    kb = '2746157';
    ver = '8.3.283.0';
    min_ver = '8.0.0.0';
  }
  else
    audit(AUDIT_INST_VER_NOT_VULN, 'Exchange', '2007 SP' + sp);
}
else if (version == 140)
{
  if (sp == 1)
  {
    kb = '2787763';
    ver = '14.1.438.0';
    min_ver = '14.1.0.0';
  }
  else if (sp == 2)
  {
    kb = '2785908';
    ver = '14.2.328.9';
    min_ver = '14.2.0.0';
  }
  else
    audit(AUDIT_INST_VER_NOT_VULN, 'Exchange', '2010 SP' + sp);
}

path = get_kb_item_or_exit('SMB/Exchange/Path', exit_code:1);
path += "\ClientAccess\Owa\Bin\DocumentViewing";
match = eregmatch(string:path, pattern:'^([A-Za-z]):.+');
if (isnull(match)) exit(1, "Error parsing path (" + path + ").");

share = match[1] + '$';
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (hotfix_is_vulnerable(path:path, file:"transcodingservice.exe", version:ver, min_version:min_ver, bulletin:bulletin, kb:kb))
{
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
