#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73417);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/07/01 20:31:47 $");

  script_cve_id("CVE-2014-1759");
  script_bugtraq_id(66622);
  script_osvdb_id(105531);
  script_xref(name:"MSFT", value:"MS14-020");
  script_xref(name:"IAVA", value:"2014-A-0050");

  script_name(english:"MS14-020: Vulnerability in Microsoft Publisher Could Allow Remote Code Execution (2950145)");
  script_summary(english:"Checks the version of Publisher");

  script_set_attribute(attribute:"synopsis", value:
"Microsoft Publisher, a component of Microsoft Office installed on the
remote host, is affected by an arbitrary pointer dereference
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Publisher component of Microsoft Office installed on the remote
host is affected by an arbitrary pointer dereference vulnerability.

A remote attacker could exploit this issue by tricking a user into
opening a specially crafted Publisher file. The attacker could then
potentially run arbitrary code as the current user.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms14-020");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Microsoft Publisher 2003
SP3 and 2007 SP3.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:publisher");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "office_installed.nasl", "ms_bulletin_checks_possible.nasl");
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

bulletin = 'MS14-020';
kbs = make_list("2817565", "2878299");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

installs = get_kb_list_or_exit("SMB/Office/Publisher/*/ProductPath");
vuln = FALSE;
foreach install (keys(installs))
{
  version = install - 'SMB/Office/Publisher/' - '/ProductPath';
  path = installs[install];
  if (isnull(path)) continue;

  path = ereg_replace(pattern:'(^[A-Za-z]:\\\\.*\\\\).*', replace:"\1", string:path);

  v = split(version, sep:'.', keep:FALSE);
  for (i = 0; i < max_index(v); i++)
    v[i] = int(v[i]);

  # Office 2003 SP3
  if (v[0] == 11 && v[1] == 0 && v[2] >= 8166)
  {
    # Check the Pubconv.dll
    share = hotfix_path2share(path:path);
    if (is_accessible_share(share:share))
    {
      check_file = "Pubconv.dll";
      old_report = hotfix_get_report();

      if (hotfix_check_fversion(path:path, file:check_file, version:"11.0.8410.0", min_version:"11.0.0.0") == HCF_OLDER)
      {
        file = ereg_replace(pattern:"^[A-Za-z]:(.*)", string:path, replace:"\1" + check_file);
        kb_name = "SMB/FileVersions/"+tolower(share-'$')+tolower(str_replace(string:file, find:"\", replace:"/"));
        fversion = get_kb_item(kb_name);

        info =
              '\n  Product           : Publisher 2003 SP3' +
              '\n  File              : ' + path + '\\' + check_file +
              '\n  Installed version : ' + fversion +
              '\n  Fixed version     : 11.0.8410.0' + '\n';

        hcf_report = '';
        hotfix_add_report(old_report + info, bulletin:bulletin, kb:"2878299");
        vuln = TRUE;
      }
      NetUseDel(close:FALSE);
    }
  }

  # Office 2007 SP3
  else if (v[0] == 12 && v[1] == 0 && v[2] >= 6606)
  {
    share = hotfix_path2share(path:path);
    if (is_accessible_share(share:share))
    {
      check_file = "Pubconv.dll";
      old_report = hotfix_get_report();

      if (hotfix_check_fversion(path:path, file:check_file, version:"12.0.6694.5000", min_version:"12.0.6606.1000") == HCF_OLDER)
      {
        file = ereg_replace(pattern:"^[A-Za-z]:(.*)", string:path, replace:"\1" + check_file);
        kb_name = "SMB/FileVersions/"+tolower(share-'$')+tolower(str_replace(string:file, find:"\", replace:"/"));
        fversion = get_kb_item(kb_name);

        info =
              '\n  Product           : Publisher 2007 SP3' +
              '\n  File              : ' + path + '\\' + check_file +
              '\n  Installed version : ' + fversion +
              '\n  Fixed version     : 12.0.6694.5000' + '\n';

        hcf_report = '';
        hotfix_add_report(old_report + info, bulletin:bulletin, kb:"2817565");
        vuln = TRUE;
      }
      NetUseDel(close:FALSE);
    }
  }
}

if (vuln)
{
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
