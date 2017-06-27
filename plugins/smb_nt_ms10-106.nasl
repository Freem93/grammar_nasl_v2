#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(51178);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2016/06/30 19:55:38 $");

  script_cve_id("CVE-2010-3937");
  script_bugtraq_id(45297);
  script_osvdb_id(69810);
  script_xref(name:"MSFT", value:"MS10-106");

  script_name(english:"MS10-106: Vulnerability in Microsoft Exchange Server Could Allow Denial of Service (2407132)");
  script_summary(english:"Checks version of Microsoft.exchange.rpc.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote mail server has a denial of service vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Microsoft Exchange 2007 running on the remote host has
a denial of service vulnerability.  The Exchange service does not
process specially crafted RPC calls correctly, resulting in an
infinite loop.

A remote, authenticated attacker could exploit this by making a
specially crafted RPC call, causing the service to become
non-responsive."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS10-106");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a patch for Microsoft Exchange 2007 SP2 for x64
systems."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/12/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:exchange_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, 'Host/patch_management_checks');

  exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");



get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS10-106';
kbs = make_list("2407132");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);


get_kb_item_or_exit("SMB/Registry/Enumerated");

version = get_kb_item_or_exit('SMB/Exchange/Version', exit_code:1);
if (version != 80) exit(0, 'Exchange version '+version+' is not affected.');

arch = get_kb_item_or_exit('SMB/ARCH', exit_code:1);
if (arch != 'x64') exit(0, 'Exchange 2007 is only affected on x64 systems.');

# Only SP2 is listed as affected, but SP1 is unsupported. Might as well
# flag that too
sp = get_kb_item_or_exit('SMB/Exchange/SP', exit_code:1);
if (sp > 2) exit(0, 'Exchange 2007 SP '+sp+' is not affected.');

path = get_kb_item_or_exit('SMB/Exchange/Path', exit_code:1);
path += "\Bin";
match = eregmatch(string:path, pattern:'^([A-Za-z]):.+');
if (isnull(match)) exit(1, "Error parsing path (" + path + ").");

share = match[1] + '$';
if (!is_accessible_share(share:share)) exit(1, "Can't connect to '"+share+"' share.");

if (hotfix_is_vulnerable(path:path, file:"Microsoft.exchange.rpc.dll", version:"8.2.253.0", min_version:"8.0.0.0", bulletin:bulletin, kb:"2407132"))
{
  set_kb_item(name:'SMB/Missing/MS10-106', value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  exit(0, 'The host is not affected.');
}
