#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77166);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/11/18 02:26:38 $");

  script_cve_id("CVE-2014-2815");
  script_bugtraq_id(69098);
  script_osvdb_id(109939);
  script_xref(name:"MSFT", value:"MS14-048");
  script_xref(name:"IAVB", value:"2014-B-0109");

  script_name(english:"MS14-048: Vulnerability in OneNote Could Allow Remote Code Execution (2977201)");
  script_summary(english:"Determines the version of ONENOTE.EXE.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application that is affected by a remote
code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft OneNote that is
affected by a remote code execution vulnerability. By convincing a
user to open a specially crafted OneNote file, a remote attacker can
create an executable file in a Startup folder and thereby execute
arbitrary code with current user rights.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS14-048");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for OneNote 2007 SP3.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:onenote");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "onenote_installed.nbin", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, 'Host/patch_management_checks');
  exit(0);
}

include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");
include("install_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS14-048';
kb = "2596857";
kbs = make_list(kb);

if (get_kb_item("Host/patch_management_checks"))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

app = 'Microsoft OneNote';

get_install_count(app_name:app, exit_if_zero:TRUE);

vuln = 0;

installs = get_installs(app_name:app);
if (installs[0] == IF_NOT_FOUND) audit(AUDIT_NOT_INST, app);

foreach install (installs[1])
{
  product = install['product'];
  sp = install['sp'];
  path = install['path'];
  version = install['version'];
  if (version == UNKNOWN_VER) continue;

  # Check Product
  if (product == '2007' && sp == '3')
  {
    v = split(version, sep:'.', keep:FALSE);

    # Check to see if the version is vulnerable
    if (
      (int(v[0]) == 12 && int(v[1]) == 0 && int(v[2]) < 6650) ||
      (int(v[0]) == 12 && int(v[1]) == 0 && int(v[2]) == 6650 && int(v[3]) < 5000)
    )
    {
      vuln++;
      info =
        '\n  Product           : Microsoft OneNote 2007 SP3' +
        '\n  Path              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 12.0.6650.5000\n';
      hotfix_add_report(info, bulletin:bulletin, kb:kb);
    }
  }
}

if (vuln)
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
