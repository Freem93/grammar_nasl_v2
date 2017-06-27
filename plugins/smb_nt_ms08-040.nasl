#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(33444);
 script_version("$Revision: 1.28 $");
 script_cvs_date("$Date: 2016/12/09 20:54:59 $");

 script_cve_id(
   "CVE-2008-0085",
   "CVE-2008-0086",
   "CVE-2008-0106",
   "CVE-2008-0107"
 );
 script_bugtraq_id(30082, 30083, 30118, 30119);
 script_osvdb_id(46770, 46771, 46772, 46773);
 script_xref(name:"MSFT", value:"MS08-040");

 script_name(english:"MS08-040: Vulnerabilities in Microsoft SQL Server Could Allow Elevation of Privilege (941203)");
 script_summary(english:"Determines the version of SQL Server");

 script_set_attribute(attribute:"synopsis", value:
"The remote Microsoft SQL Server install is vulnerable to memory
corruption flaws.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft SQL Server, Desktop
Engine or Internal Database that is vulnerable to multiple memory
corruption issues.

These vulnerabilities may allow an attacker to gain elevates
privileges on the server.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms08-040");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for SQL Server 7, 2000 and
2005.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(119, 189, 200);

 script_set_attribute(attribute:"vuln_publication_date", value:"2008/07/08");
 script_set_attribute(attribute:"patch_publication_date", value:"2008/07/08");
 script_set_attribute(attribute:"plugin_publication_date", value:"2008/07/08");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sql_server");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:data_engine");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

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

bulletin = 'MS08-040';
kb       = '941203';

kbs = make_list(kb);
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

  if ( ( hotfix_check_fversion(path:rootfile, file:"Sqlservr.exe", version:"2000.80.2050.0", min_version:"2000.80.2000.0", bulletin:bulletin, kb:kb) == HCF_OLDER ) ||
       ( hotfix_check_fversion(path:rootfile, file:"Sqlservr.exe", version:"2000.80.2273.0", min_version:"2000.80.2200.0", bulletin:bulletin, kb:kb) == HCF_OLDER ) ||
       ( hotfix_check_fversion(path:rootfile, file:"Sqlservr.exe", version:"2000.99.4.0", min_version:"2000.90.0.0", bulletin:bulletin, kb:kb) == HCF_OLDER ) ||
       ( hotfix_check_fversion(path:rootfile, file:"Sqlservr.exe", version:"2005.90.3068.0", min_version:"2005.90.3000.0", bulletin:bulletin, kb:kb) == HCF_OLDER ) ||
       ( hotfix_check_fversion(path:rootfile, file:"Sqlservr.exe", version:"2005.90.3233.0", min_version:"2005.90.3200.0", bulletin:bulletin, kb:kb) == HCF_OLDER ) )
  {
    set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
    hotfix_security_hole();
    vuln = TRUE;
  }
}
hotfix_check_fversion_end();
if (!vuln) audit(AUDIT_HOST_NOT, 'affected');
