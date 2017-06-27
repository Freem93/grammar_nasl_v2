#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72431);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/07/01 20:31:47 $");

  script_cve_id("CVE-2014-0294");
  script_bugtraq_id(65397);
  script_osvdb_id(103161);
  script_xref(name:"MSFT", value:"MS14-008");
  script_xref(name:"IAVA", value:"2014-A-0024");

  script_name(english:"MS14-008: Vulnerability in Microsoft Forefront Protection for Exchange Could Allow Remote Code Execution (2927022)");
  script_summary(english:"Checks version of Forefront Protection");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a security application that is affected by a code
execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Forefront Protection for Exchange installed on the
remote Windows host is potentially affected by a remote code execution
vulnerability when scanning specially crafted email messages.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms14-008");
  script_set_attribute(attribute:"solution", value:
"Microsoft has has provided updates for Microsoft Forefront Protection
for Exchange 2010.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:forefront_protection");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:microsoft:forefront_protection_for_exchange");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("microsoft_forefront_for_exchange_installed.nbin", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = "MS14-008";
kb = "2927022";

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

path = get_kb_item_or_exit("SMB/Microsoft Forefront Protection for Exchange Server/Path");
version = get_kb_item_or_exit("SMB/Microsoft Forefront Protection for Exchange Server/Version");

# This only applies to 11.0.727.0
if (ver_compare(ver:version, fix:'11.0.727.0') == 0)
{
  registry_init();
  hcf_init = TRUE;

  hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
  key = "SOFTWARE\Microsoft\Exchange\Setup\MsiInstallPath";
  exchpath = get_registry_value(handle:hklm, item:key);
  RegCloseKey(handle:hklm);
  NetUseDel(close:FALSE);

  if (exchpath)
  {
    share = hotfix_path2share(path:exchpath);
    if (!is_accessible_share(share:share))
    {
      NetUseDel();
      audit(AUDIT_SHARE_FAIL, share);
    }

    if (hotfix_is_vulnerable(path:exchpath + "\TransportRoles\agents\FSEAgent\bin", file:"Microsoft.Fss.AntiSpam.dll", version:"11.0.747.0", min_version:"11.0.0.0", bulletin:bulletin, kb:kb))
    {
      set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
      hotfix_security_hole();
      hotfix_check_fversion_end();
      exit(0);
    }
    hotfix_check_fversion_end();
  }
}
audit(AUDIT_HOST_NOT, 'affected');
