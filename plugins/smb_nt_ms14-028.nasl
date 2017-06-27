#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73987);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/02/23 22:37:42 $");

  script_cve_id("CVE-2014-0255", "CVE-2014-0256");
  script_bugtraq_id(67280, 67281);
  script_osvdb_id(106897, 106898);
  script_xref(name:"MSFT", value:"MS14-028");
  script_xref(name:"IAVB", value:"2014-B-0059");

  script_name(english:"MS14-028: Vulnerabilities in iSCSI Could Allow Denial of Service (2962485)");
  script_summary(english:"Checks version of Iscsitgt.dll");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple denial of service
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is affected by multiple denial of service
vulnerabilities due to Windows improperly handling iSCSI packets. A
remote attacker could send large amounts of specially crafted iSCSI
packets to the host and cause the system to stop responding until it
is restarted.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS14-028");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Server 2008 R2,
2012, and 2012 R2. Microsoft has announced that Windows Storage Server
2008 will not be updated and instead customers should follow the
guidelines referenced in the advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS14-028';
kb  = "2933826";
kbs = make_list("2933826", "2962073");
vuln = NULL;

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

# Only Windows Storage Server 2008, Windows Server 2008 R2, 2012, 2012 R2, and 2012 Core are affected
if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0', win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if (
  "Server 2003" >< productname ||
  "Windows Vista" >< productname ||
  "Windows 7" >< productname ||
  "Windows 8" >< productname ||
  "Windows RT" >< productname
)
  audit(AUDIT_OS_SP_NOT_VULN);

if ("Server 2008" >< productname && hotfix_check_server_core() == 1)
  exit(0, "The host is running the Server Core installation of "+productname+" and is therefore not affected.");

app = "iSCSI Software Target";

# Check that iSCSI target is installed
registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key = "SOFTWARE\Microsoft\iSCSI Target\Guid";
check = get_registry_value(handle:hklm, item:key);
RegCloseKey(handle:hklm);

if (isnull(check))
{
  close_registry();
  audit(AUDIT_NOT_INST, app);
}

# Windows Storage Server 2008 is affected but has no patch
if ("Storage Server 2008" >< productname)
{
  info = '\nNo patches are available for Windows Storage Server 2008. Please refer to the advisory for further instructions.\n';
  hotfix_add_report(info, bulletin:bulletin, kb:kb);
  vuln = TRUE;
}

# Check for iSCSI Software Target on Windows 2008 R2
if ("Server 2008 R2" >< productname || "Small Business Server 2011" >< productname)
{
  fix = "3.3.16575.0";
  ver = NULL;
  found = NULL;

  get_kb_item_or_exit("SMB/Registry/Uninstall/Enumerated");

  list = get_kb_list_or_exit("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");

  foreach key (keys(list))
  {
    displayname = list[key];
    if (displayname =~ "iSCSI Software Target")
    {
      version_key = key - 'DisplayName' + 'DisplayVersion';
      ver = get_kb_item(version_key);
      found = TRUE;
      break;
    }
  }

  if (!found)
  {
    close_registry();
    audit(AUDIT_NOT_INST, app);
  }

  if (isnull(ver))
  {
    close_registry();
    audit(AUDIT_UNKNOWN_APP_VER, app);
  }

  if (ver =~ "^3\.3($|[^0-9])" && ver_compare(ver:ver, fix:fix, strict:FALSE) == -1)
  {
    info =
      '\n  Product           : ' + app +
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : ' + fix +
      '\n';
    hotfix_add_report(info, bulletin:bulletin, kb:kb);
    vuln = TRUE;
  }
}

close_registry();

if ("Server 2012" >< productname)
{
  share = hotfix_get_systemdrive(exit_on_fail:TRUE, as_share:TRUE);
  if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

  if (
    # Windows Server 2012 R2 with KB2919355
    hotfix_is_vulnerable(os:"6.3", sp:0, file:"iscsitgt.dll", version:"6.3.9600.17095", min_version:"6.3.9600.17039", dir:"\system32", bulletin:bulletin, kb:kb) ||
    # Windows Server 2012 R2 without KB2919355
    hotfix_is_vulnerable(os:"6.3", sp:0, file:"iscsitgt.dll", version:"6.3.9600.16660", min_version:"6.3.9600.16000", dir:"\system32", bulletin:bulletin, kb:"2962073") ||

    # Windows Server 2012
    hotfix_is_vulnerable(os:"6.2", sp:0, file:"iscsitgt.dll", version:"6.2.9200.21005", min_version:"6.2.9200.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
    hotfix_is_vulnerable(os:"6.2", sp:0, file:"iscsitgt.dll", version:"6.2.9200.16886", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:kb)
  ) vuln = TRUE;

  hotfix_check_fversion_end();
}

if (vuln)
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_warning();

  exit(0);
}
else
  audit(AUDIT_HOST_NOT, 'affected');
