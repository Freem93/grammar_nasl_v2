#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35632);
  script_version("$Revision: 1.30 $");
  script_cvs_date("$Date: 2016/12/09 20:55:00 $");

  script_cve_id("CVE-2008-5416");
  script_bugtraq_id(32710);
  script_osvdb_id(50589);
  script_xref(name:"MSFT", value:"MS09-004");
  script_xref(name:"IAVA", value:"2009-A-0012");
  script_xref(name:"CERT", value:"696644");
  script_xref(name:"EDB-ID", value:"7501");
  script_xref(name:"EDB-ID", value:"16392");
  script_xref(name:"EDB-ID", value:"16396");

  script_name(english:"MS09-004: Vulnerability in Microsoft SQL Server Could Allow Remote Code Execution (959420)");
  script_summary(english:"Determines the version of SQL Server");

  script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Microsoft SQL
Server.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft SQL Server, Desktop
Engine or Internal Database that suffers from an authenticated, remote
code execution vulnerability in the extended stored procedure
'sp_replwritetovarbin' due to an invalid parameter check.

Successful exploitation could allow an attacker to take complete
control of the affected system.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms09-004");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for SQL Server 2000 and 2005.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'MS09-004 Microsoft SQL Server sp_replwritetovarbin Memory Corruption via SQL Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/12/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/02/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/02/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sql_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "mssql_version.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, 1433, "Services/mssql", 'Host/patch_management_checks');

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS09-004';
kbs = make_list("960082", "960083", "960089", "960090");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

ver_list = get_kb_list("mssql/installs/*/SQLVersion");
if (isnull(ver_list)) audit(AUDIT_NOT_INST, "Microsoft SQL Server");

vuln = FALSE;

foreach item (keys(ver_list))
{
  item -= 'mssql/installs/';
  item -= '/SQLVersion';
  rootfile = item;

  share = hotfix_path2share(path:rootfile);
  if (!is_accessible_share(share:share)) continue;

  if (
    (hotfix_check_fversion(path:rootfile, file:"Sqlservr.exe", version:"2000.80.2055.0", min_version:"2000.80.2000.0", bulletin:bulletin, kb:"960082") == HCF_OLDER) ||
    (hotfix_check_fversion(path:rootfile, file:"Sqlservr.exe", version:"2000.80.2282.0", min_version:"2000.80.2200.0", bulletin:bulletin, kb:"960083") == HCF_OLDER) ||
    (hotfix_check_fversion(path:rootfile, file:"Sqlservr.exe", version:"2005.90.3077.0", min_version:"2005.90.3000.0", bulletin:bulletin, kb:"960089") == HCF_OLDER) ||
    (hotfix_check_fversion(path:rootfile, file:"Sqlservr.exe", version:"2005.90.3310.0", min_version:"2005.90.3200.0", bulletin:bulletin, kb:"960090") == HCF_OLDER)
  )
  {
    set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
    hotfix_security_hole();
    vuln = TRUE;
  }
}

hotfix_check_fversion_end();
if (!vuln) audit(AUDIT_HOST_NOT, 'affected');
