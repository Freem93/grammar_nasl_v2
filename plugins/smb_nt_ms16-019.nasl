#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88651);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/08/26 19:16:56 $");

  script_cve_id("CVE-2016-0033", "CVE-2016-0047");
  script_bugtraq_id(82717, 82738);
  script_osvdb_id(134323, 134324);
  script_xref(name:"MSFT", value:"MS16-019");
  script_xref(name:"IAVB", value:"2016-B-0024");

  script_name(english:"MS16-019: Security Update for .NET Framework to Address Denial of Service (3137893)");
  script_summary(english:"Checks the file versions.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing a security update. It is,
therefore, affected by multiple vulnerabilities in the .NET
Framework :

  - A denial of service vulnerability exists due to improper
    handling of certain Extensible Stylesheet Language
    Transformations (XSLT). A remote attacker can exploit
    this, via specially crafted XSLT inserted into a
    client-side web part, to cause the server to recursively
    compile XSLT transforms, resulting in significant
    degradation of server performance. (CVE-2016-0033)

  - An information disclosure vulnerability exists in
    Windows Forms due to improper handling of icon data.
    A remote attacker can exploit this, by uploading a
    specially crafted icon, to capture information that is
    returned within the icon's data. (CVE-2016-0047)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/en-us/library/MS16-019.aspx");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for .NET framework 2.0 SP2,
3.5, 3.5.1, 4, 4.5.1, 4.5.2, 4.6, and 4.6.1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_framework");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl", "microsoft_net_framework_installed.nasl");
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

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

global_var bulletin, vuln, arch;

arch = get_kb_item_or_exit('SMB/ARCH');
vuln = 0;
bulletin = 'MS16-019';

kbs = make_list(
  "3122646", #
  "3122648", #
  "3122649", #
  "3122651", #
  "3122654", #
  "3122655", #
  "3122656", #
  "3122658", #
  "3122660", #
  "3122661", #
  "3127219", #
  "3127220", #
  "3127221", #
  "3127222", #
  "3127226", #
  "3127227", #
  "3127230", #
  "3127231", #
  "3127233", #
  "3135173",
  "3135174"
);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
winver = get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);
if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0', win81:'0', win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows 8" >< productname && "Windows 8.1" >!< productname) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(exit_on_fail:TRUE, as_share:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

# dotnet checks
function perform_dotnet_checks()
{
  local_var dotnet_452_installed, dotnet_46_installed, dotnet_461_installed, dotnet_35_installed;
  local_var ver, missing, count, installs, install;

  # Determine if .NET 4.5.2 or 4.6 is installed
  dotnet_452_installed = FALSE;
  dotnet_46_installed  = FALSE;
  dotnet_461_installed = FALSE;
  dotnet_35_installed  = FALSE;

  # Make sure to add dependency for microsoft_net_framework_installed.nasl
  count = get_install_count(app_name:'Microsoft .NET Framework');
  if (count > 0)
  {
    installs = get_installs(app_name:'Microsoft .NET Framework');
    foreach install(installs[1])
    {
      ver = install["version"];
      if (ver == "4.6.1") dotnet_461_installed = TRUE;
      if (ver == "4.6") dotnet_46_installed = TRUE;
      if (ver == "4.5.2") dotnet_452_installed = TRUE;
      if (ver == "3.5") dotnet_35_installed = TRUE;
    }
  }

  ########## KB3122646 #############
  # .NET Framework 2.0 SP2         #
  # Windows Vista SP2              #
  # Windows Server 2008 SP2        #
  ##################################
  missing = 0;
  missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"system.xml.dll", version:"2.0.50727.4260", min_version:"2.0.50727.0",    dir:"\Microsoft.NET\Framework\v2.0.50727");
  missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"system.xml.dll", version:"2.0.50727.8679", min_version:"2.0.50727.6500", dir:"\Microsoft.NET\Framework\v2.0.50727");

  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3122646");
  vuln += missing;

  if(dotnet_35_installed)
  {
    ########### KB3122648 #############
    # .NET Framework 3.5.1            #
    # Windows 7 SP1                   #
    # Windows Server 2008 R2 SP1      #
    ###################################
    missing = 0;
    missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"system.xml.dll", version:"2.0.50727.5494", min_version:"2.0.50727.0",    dir:"\Microsoft.NET\Framework\v2.0.50727");
    missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"system.xml.dll", version:"2.0.50727.8679", min_version:"2.0.50727.6500", dir:"\Microsoft.NET\Framework\v2.0.50727");

    if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3122648");
    vuln += missing;

    ########### KB3122649 ###########
    # .NET Framework 3.5            #
    # Windows Server 2012           #
    #################################
    missing = 0;
    missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"system.xml.dll", version:"2.0.50727.6430", min_version:"2.0.50727.0",    dir:"\Microsoft.NET\Framework\v2.0.50727");
    missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"system.xml.dll", version:"2.0.50727.8679", min_version:"2.0.50727.7500", dir:"\Microsoft.NET\Framework\v2.0.50727");

    if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3122649");
    vuln += missing;

    ############ KB3122651 ############
    # .NET Framework 3.5              #
    # Windows 8.1                     #
    # Windows Server 2012 R2          #
    ###################################
    missing = 0;
    missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"system.xml.dll", version:"2.0.50727.8018", min_version:"2.0.50727.0",    dir:"\Microsoft.NET\Framework\v2.0.50727");
    missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"system.xml.dll", version:"2.0.50727.8679", min_version:"2.0.50727.8300", dir:"\Microsoft.NET\Framework\v2.0.50727");

    if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3122651");
    vuln += missing;
  }

  ############ KB3122654 ############
  # .NET Framework 4.5.2            #
  # Windows 8.1                     #
  # Windows Server 2012 R2          #
  ###################################
  if (dotnet_452_installed)
  {
    missing = 0;
    missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"system.xml.dll", version:"4.0.30319.34281", min_version:"4.0.30319.0",     dir:"\Microsoft.NET\Framework\v4.0.30319");
    missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"system.xml.dll", version:"4.0.30319.36334", min_version:"4.0.30319.35000", dir:"\Microsoft.NET\Framework\v4.0.30319");

    if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3122654");
    vuln += missing;
  }

  ########### KB3122655 ###########
  # .NET Framework 4.5.2          #
  # Windows Server 2012           #
  #################################
  if (dotnet_452_installed)
  {
    missing = 0;
    missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"system.xml.dll", version:"4.0.30319.34281", min_version:"4.0.30319.0",     dir:"\Microsoft.NET\Framework\v4.0.30319");
    missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"system.xml.dll", version:"4.0.30319.36334", min_version:"4.0.30319.35000", dir:"\Microsoft.NET\Framework\v4.0.30319");

    if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3122655");
    vuln += missing;
  }


  ########## KB3122656 #############
  # .NET Framework 4.5.2           #
  # Windows Vista SP2              #
  # Windows Server 2008 SP2        #
  # Windows 7 SP1                  #
  # Windows Server 2008 R2 SP1     #
  ##################################
  if (dotnet_452_installed)
  {
    missing = 0;
    missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"system.xml.dll", version:"4.0.30319.34283", min_version:"4.0.30319.0",     dir:"\Microsoft.NET\Framework\v4.0.30319");
    missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"system.xml.dll", version:"4.0.30319.36336", min_version:"4.0.30319.35000", dir:"\Microsoft.NET\Framework\v4.0.30319");
    missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"system.xml.dll", version:"4.0.30319.34283", min_version:"4.0.30319.0",     dir:"\Microsoft.NET\Framework\v4.0.30319");
    missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"system.xml.dll", version:"4.0.30319.36336", min_version:"4.0.30319.35000", dir:"\Microsoft.NET\Framework\v4.0.30319");

    if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3122656");
    vuln += missing;
  }

  ########### KB3122658 ###########
  # .NET Framework 4.6 / 4.6.1    #
  # Windows Server 2012           #
  #################################
  if (dotnet_46_installed || dotnet_461_installed)
  {
    missing = 0;
    missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"system.xml.dll", version:"4.6.1064.2", min_version:"4.6.0.0", dir:"\Microsoft.NET\Framework\v4.0.30319");

    if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3122658");
    vuln += missing;
  }

  ############ KB3122660 ############
  # .NET Framework 4.6 / 4.6.1      #
  # Windows 8.1                     #
  # Windows Server 2012 R2          #
  ###################################
  if (dotnet_46_installed || dotnet_461_installed)
  {
    missing = 0;
    missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"system.xml.dll", version:"4.6.1064.2", min_version:"4.6.0.0", dir:"\Microsoft.NET\Framework\v4.0.30319");

    if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3122660");
    vuln += missing;
  }

  ########## KB3122661 #############
  # .NET Framework 4.6             #
  # Windows Vista SP2              #
  # Windows Server 2008 SP2        #
  # Windows 7 SP1                  #
  ##################################
  if (dotnet_46_installed || dotnet_461_installed)
  {
    missing = 0;
    missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"system.xml.dll", version:"4.6.1067.0", min_version:"4.6.0.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
    missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"system.xml.dll", version:"4.6.1067.0", min_version:"4.6.0.0", dir:"\Microsoft.NET\Framework\v4.0.30319");

    if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3122661");
    vuln += missing;
  }


  ########## KB3127219 #############
  # .NET Framework 2.0 SP2         #
  # Windows Vista SP2              #
  # Windows Server 2008 SP2        #
  ##################################
  missing = 0;
  missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"system.drawing.dll", version:"2.0.50727.4261", min_version:"2.0.50727.0",    dir:"\Microsoft.NET\Framework\v2.0.50727");
  missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"system.drawing.dll", version:"2.0.50727.8681", min_version:"2.0.50727.6500", dir:"\Microsoft.NET\Framework\v2.0.50727");

  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3127219");
  vuln += missing;

  ########### KB3127220 #############
  # .NET Framework 3.5.1            #
  # Windows 7 SP1                   #
  # Windows Server 2008 R2 SP1      #
  ###################################
  missing = 0;
  missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"system.drawing.dll", version:"2.0.50727.5495", min_version:"2.0.50727.0",    dir:"\Microsoft.NET\Framework\v2.0.50727");
  missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"system.drawing.dll", version:"2.0.50727.8681", min_version:"2.0.50727.6500", dir:"\Microsoft.NET\Framework\v2.0.50727");

  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3127220");
  vuln += missing;

  ########### KB3127221 ###########
  # .NET Framework 3.5            #
  # Windows Server 2012           #
  #################################
  missing = 0;
  missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"system.drawing.dll", version:"2.0.50727.6431", min_version:"2.0.50727.0",    dir:"\Microsoft.NET\Framework\v2.0.50727");
  missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"system.drawing.dll", version:"2.0.50727.8681", min_version:"2.0.50727.7500", dir:"\Microsoft.NET\Framework\v2.0.50727");

  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3127221");
  vuln += missing;

  ############ KB3127222 ############
  # .NET Framework 3.5              #
  # Windows 8.1                     #
  # Windows Server 2012 R2          #
  ###################################
  missing = 0;
  missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"system.drawing.dll", version:"2.0.50727.8019", min_version:"2.0.50727.0",    dir:"\Microsoft.NET\Framework\v2.0.50727");
  missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"system.drawing.dll", version:"2.0.50727.8681", min_version:"2.0.50727.8300", dir:"\Microsoft.NET\Framework\v2.0.50727");

  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3127222");
  vuln += missing;

  ############ KB3127226 ############
  # .NET Framework 4.5.2            #
  # Windows 8.1                     #
  # Windows Server 2012 R2          #
  ###################################
  if (dotnet_452_installed)
  {
    missing = 0;
    missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"system.drawing.dll", version:"4.0.30319.34284", min_version:"4.0.30319.0",     dir:"\Microsoft.NET\Framework\v4.0.30319");
    missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"system.drawing.dll", version:"4.0.30319.36337", min_version:"4.0.30319.35000", dir:"\Microsoft.NET\Framework\v4.0.30319");

    if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3127226");
    vuln += missing;
  }

  ########### KB3127227 ###########
  # .NET Framework 4.5.2          #
  # Windows Server 2012           #
  #################################
  if (dotnet_452_installed)
  {
    missing = 0;
    missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"system.drawing.dll", version:"4.0.30319.34284", min_version:"4.0.30319.0",     dir:"\Microsoft.NET\Framework\v4.0.30319");
    missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"system.drawing.dll", version:"4.0.30319.36337", min_version:"4.0.30319.35000", dir:"\Microsoft.NET\Framework\v4.0.30319");

    if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3127227");
    vuln += missing;
  }

  ########### KB3127230 ###########
  # .NET Framework 4.6 / 4.6.1    #
  # Windows Server 2012           #
  #################################
  if (dotnet_46_installed || dotnet_461_installed)
  {
    missing = 0;
    missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"system.drawing.dll", version:"4.6.1068.2", min_version:"4.6.0.0", dir:"\Microsoft.NET\Framework\v4.0.30319");

    if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3127230");
    vuln += missing;
  }

  ############ KB3127231 ############
  # .NET Framework 4.6 / 4.6.1      #
  # Windows 8.1                     #
  # Windows Server 2012 R2          #
  ###################################
  if (dotnet_46_installed || dotnet_461_installed)
  {
    missing = 0;
    missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"system.drawing.dll", version:"4.6.1068.2", min_version:"4.6.0.0", dir:"\Microsoft.NET\Framework\v4.0.30319");

    if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3127231");
    vuln += missing;
  }

  ########## KB3127233 #############
  # .NET Framework 4.6             #
  # Windows Vista SP2              #
  # Windows Server 2008 SP2        #
  # Windows 7 SP1                  #
  #  Windows Server 2008 R2 SP1    #
  ##################################
  if (dotnet_46_installed || dotnet_461_installed)
  {
    missing = 0;
    missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"system.drawing.dll", version:"4.6.1068.2", min_version:"4.6.0.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
    missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"system.drawing.dll", version:"4.6.1068.2", min_version:"4.6.0.0", dir:"\Microsoft.NET\Framework\v4.0.30319");

    if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3127233");
    vuln += missing;
  }

  ############# KB3135174 #############
  #  .NET Framework 3.5               #
  #  Windows 10                       #
  #####################################
  if (dotnet_35_installed)
  {
    #  3.5 is optional addon in 10
    missing = 0;
    missing += hotfix_is_vulnerable(os:"10", sp:0, file:"system.xml.dll", version:"2.0.50727.8679", min_version:"2.0.50727.6500", dir:"\Microsoft.NET\Framework\v2.0.50727");

    if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3135174");
    vuln += missing;
  }

  ############# KB3135173 #############
  #  .NET Framework 4.6               #
  #  Windows 10                       #
  #####################################
  missing = 0;
  missing += hotfix_is_vulnerable(os:"10", sp:0, file:"system.xml.dll", version:"4.6.1064.2", min_version:"4.6.0.0", dir:"\Microsoft.NET\Framework\v4.0.30319");

  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3135173");
  vuln += missing;
}

perform_dotnet_checks();

if(vuln)
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
