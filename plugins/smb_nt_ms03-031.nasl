#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11804);
 script_version("$Revision: 1.36 $");
 script_cvs_date("$Date: 2017/05/25 13:29:27 $");

 script_cve_id("CVE-2003-0230", "CVE-2003-0231", "CVE-2003-0232");
 script_bugtraq_id(8274, 8275, 8276);
 script_osvdb_id(2299, 10123, 10125);
 script_xref(name:"MSFT", value:"MS03-031");
 script_xref(name:"CERT", value:"918652");
 script_xref(name:"CERT", value:"584868");
 script_xref(name:"CERT", value:"556356");
 script_xref(name:"MSKB", value:"815495");

 script_name(english:"MS03-031: Cumulative Patch for MS SQL Server (815495)");
 script_summary(english:"Microsoft's SQL Version Query");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the SQL
service.");
 script_set_attribute(attribute:"description", value:
"The remote Microsoft SQL server is vulnerable to several flaws :

  - Named pipe hijacking
  - Named Pipe Denial of Service
  - SQL server buffer overrun

These flaws could allow a user to gain elevated privileges on this
host.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms03-031");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for MSSQL 7 and 2000.");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L");
 script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(264);

 script_set_attribute(attribute:"vuln_publication_date", value:"2003/07/03");
 script_set_attribute(attribute:"patch_publication_date", value:"2003/07/23");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/07/24");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:data_engine");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sql_server");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2017 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

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

bulletin = 'MS03-031';
kb = "815495";

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit('SMB/Registry/Enumerated');
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

path = hotfix_get_mssqldir();
if (!path) exit(0, "MS SQL does not appear to be installed.");

if (!is_accessible_share()) exit(1, "is_accessible_share() failed.");


if (
  (hotfix_check_fversion(path:path, file:"sqlrepss.dll", version:"2000.80.765.0", min_version:"2000.80.0.0", bulletin:bulletin, kb:kb) == HCF_OLDER) ||
  (hotfix_check_fversion(path:path, file:"ums.dll",      version:"2000.33.25.0",  min_version:"2000.33.0.0", bulletin:bulletin, kb:kb) == HCF_OLDER)
)
{
  hotfix_security_warning();
  hotfix_check_fversion_end();

  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  exit(0, "The host is not affected.");
}
