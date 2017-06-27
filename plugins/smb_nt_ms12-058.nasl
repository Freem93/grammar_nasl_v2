#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(61533);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/07/01 20:31:47 $");

  script_cve_id(
    "CVE-2012-1766",
    "CVE-2012-1767",
    "CVE-2012-1768",
    "CVE-2012-1769",
    "CVE-2012-1770",
    "CVE-2012-1771",
    "CVE-2012-1772",
    "CVE-2012-1773",
    "CVE-2012-3106",
    "CVE-2012-3107",
    "CVE-2012-3108",
    "CVE-2012-3109",
    "CVE-2012-3110"
  );
  script_bugtraq_id(
    54497,
    54500,
    54504,
    54506,
    54511,
    54531,
    54536,
    54541,
    54543,
    54546,
    54548,
    54550,
    54554
  );
  script_osvdb_id(
    83900,
    83901,
    83902,
    83903,
    83904,
    83905,
    83906,
    83907,
    83908,
    83909,
    83910,
    83911,
    83913,
    83944
  );
  script_xref(name:"CERT", value:"118913");
  script_xref(name:"MSFT", value:"MS12-058");
  script_xref(name:"Secunia", value:"49936");

  script_name(english:"MS12-058: Vulnerabilities in Microsoft Exchange Server WebReady Document Viewing Could Allow Remote Code Execution (2740358)");
  script_summary(english:"Checks version of transcodingservice.exe");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote mail server has multiple code execution vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Microsoft Exchange running on the remote host is using
a vulnerable set of the Oracle Outside In libraries.  These libraries
are used by the WebReady Document Viewing feature to display certain
kinds of attachments viewed via Outlook Web App (OWA).  An attacker
could exploit this by sending a malicious email attachment to a user
who views it in OWA, resulting in arbitrary code execution as
LocalService."
  );
  # http://www.protekresearchlab.com/index.php?option=com_content&view=article&id=57&Itemid=57
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a339f216");
  # http://www.protekresearchlab.com/index.php?option=com_content&view=article&id=58&Itemid=58
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?689a4e3d");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/advisory/2737111");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms12-058");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Exchange 2007 and 2010.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-12-497");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/15");

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

bulletin = 'MS12-058';
kbs = make_list('2706690', '2734323', '2743248');

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
    kb = '2734323';
    ver = '8.3.279.4';
    min_ver = '8.0.0.0';
  }
  else
    audit(AUDIT_INST_VER_NOT_VULN, 'Exchange', '2007 SP' + sp);
}
else if (version == 140)
{
  if (sp == 1)
  {
    kb = '2743248';
    ver = '14.1.421.2';
    min_ver = '14.1.0.0';
  }
  else if (sp == 2)
  {
    kb = '2706690';
    ver = '14.2.318.4';
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
