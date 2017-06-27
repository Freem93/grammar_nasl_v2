#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96391);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/05/26 23:57:36 $");

  script_cve_id("CVE-2017-0003");
  script_osvdb_id(149885);
  script_xref(name:"MSFT", value:"MS17-002");
  script_xref(name:"MSKB", value:"3128057");
  script_xref(name:"MSKB", value:"3141486");
  script_xref(name:"IAVA", value:"2017-A-0009");

  script_name(english:"MS17-002: Security Update for Microsoft Office (3214291)");
  script_summary(english:"Checks the file versions.");

  script_set_attribute(attribute:"synopsis",value:
"An application installed on the remote host is affected by a remote
code execution vulnerability.");
  script_set_attribute(attribute:"description",value:
"The version of Microsoft Word or Microsoft SharePoint Server installed
on the remote Windows host is missing a security update. It is,
therefore, affected by a memory corruption issue due to improper
handling of objects in memory. An unauthenticated, remote attacker can
exploit this, by convincing a user to visit a specially crafted
website or open a specially crafted Office file, to execute arbitrary
code in the context of the current user.");
  script_set_attribute(attribute:"see_also",value:"https://technet.microsoft.com/library/security/MS17-002");
  script_set_attribute(attribute:"solution",value:
"Microsoft has released a set of patches for Microsoft Word 2016 and
SharePoint Server 2016");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/10");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_server");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies(
    "office_installed.nasl",
    "microsoft_sharepoint_installed.nbin",
    "smb_hotfixes.nasl",
    "ms_bulletin_checks_possible.nasl"
  );
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
include("install_func.inc");

global_var bulletin, vuln;

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS17-002';
kbs = make_list(
  '3128057', # Word 2016
  '3141486'  # SharePoint Server 2016
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

# Get path information for Windows.
windir = hotfix_get_systemroot();
if (isnull(windir)) exit(1, "Failed to determine the location of %windir%.");

registry_init();

vuln = FALSE;

######################################################################
# Word 2016
######################################################################
function perform_word_checks()
{
  local_var word_checks;

  word_checks = make_array(
    "16.0", make_nested_list(
      make_array("sp", 0, "version", "16.0.4483.1000", "channel", "MSI", "kb", "3128057"),
      make_array("sp", 0, "version", "16.0.6741.2105", "channel", "Deferred", "channel_version", "1602", "kb", "3128057"),
      make_array("sp", 0, "version", "16.0.6965.2117", "channel", "Deferred", "channel_version", "1605", "kb", "3128057"),
      make_array("sp", 0, "version", "16.0.7369.2102", "channel", "First Release for Deferred", "kb", "3128057"),
      make_array("sp", 0, "version", "16.0.7571.2109", "channel", "Current", "kb", "3128057")
    )
  );
  if (hotfix_check_office_product(product:"Word", checks:word_checks, bulletin:bulletin))
    vuln = TRUE;
}

######################################################################
# SharePoint Server 2016
######################################################################
function perform_sharepoint_checks()
{
  local_var installs, install, path;

  installs = get_installs(app_name:"Microsoft SharePoint Server");
  foreach install (installs[1])
  {
    if (install["Product"] == "2016" &&
        !isnull(install['path']) &&
        install['SP'] == '0' &&
        install['Edition'] == 'Server')
    {
      path = hotfix_append_path(path:install['path'], value:"WebServices\ConversionServices");
      if (hotfix_check_fversion(file:"sword.dll", version:"16.0.4483.1000", min_version:"16.0.0.0", path:path, bulletin:bulletin, kb:"3141486", product:"Office SharePoint Server 2016") == HCF_OLDER)
        vuln = TRUE;
    }
  }
}

perform_word_checks();
perform_sharepoint_checks();

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
