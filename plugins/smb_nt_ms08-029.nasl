#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(32313);
 script_version("$Revision: 1.21 $");
 script_cvs_date("$Date: 2016/06/30 19:55:38 $");

 script_cve_id("CVE-2008-1437","CVE-2008-1438");
 script_bugtraq_id(29060, 29073);
 script_osvdb_id(45027, 45028);
 script_xref(name:"MSFT", value:"MS08-029");

 script_name(english:"MS08-029: Vulnerabilities in Microsoft Malware Protection Engine Could Allow Denial of Service (952044)");
 script_summary(english:"Determines the version of Malware Protection Engine.");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to crash the antimalware program.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Windows Malware Protection
engine that is vulnerable to a bug in the file handling routine which
could allow an attacker to crash the protection engine.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms08-029");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Defender and Live
OneCare.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(399);

 script_set_attribute(attribute:"vuln_publication_date", value:"2008/05/13");
 script_set_attribute(attribute:"patch_publication_date", value:"2008/05/13");
 script_set_attribute(attribute:"plugin_publication_date", value:"2008/05/13");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:windows_defender");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:windows_live_onecare");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:antigen");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:forefront_client_security");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:forefront_security");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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
include("smb_reg_query.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS08-029';
kbs = make_list("952044");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

if (hotfix_check_sp_range(xp:'0,2', vista:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ('XP' >!< productname && 'Vista' >!< productname) exit(0, "The host is running " + productname + " and hence is not affected.");

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

keys = make_list (
	"SOFTWARE\Microsoft\Windows Defender\Signature Updates",
	"SOFTWARE\Microsoft\OneCare Protection\Signature Updates"
);

kb = '952044';
foreach key (keys)
{
  version = NULL;
  version = get_registry_value(handle:hklm, item:key + "\EngineVersion");

  if (!isnull(version))
  {
    if (ver_compare(ver:version, fix:'1.1.3520', strict:FALSE) < 0)
    {
      RegCloseKey(handle:hklm);
      set_kb_item(name:"SMB/Missing/MS08-029", value:TRUE);
      hotfix_add_report(bulletin:bulletin, kb:kb);
      hotfix_security_warning();
      hotfix_check_fversion_end();
      exit(0);
    }
  }
}
RegCloseKey(handle:hklm);
hotfix_check_fversion_end();
audit(AUDIT_HOST_NOT, 'affected');
