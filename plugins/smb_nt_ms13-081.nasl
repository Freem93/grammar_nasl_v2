#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70333);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/12/09 21:04:54 $");

  script_cve_id(
    "CVE-2013-3128",
    "CVE-2013-3200",
    "CVE-2013-3879",
    "CVE-2013-3880",
    "CVE-2013-3881",
    "CVE-2013-3888",
    "CVE-2013-3894"
  );
  script_bugtraq_id(
    62819,
    62821,
    62823,
    62828,
    62830,
    62831,
    62833
  );
  script_osvdb_id(
    98208,
    98209,
    98210,
    98211,
    98212,
    98213,
    98214
  );
  script_xref(name:"MSFT", value:"MS13-081");

  script_name(english:"MS13-081: Vulnerabilities in Windows Kernel-Mode Drivers Could Allow Remote Code Execution (2870008)");
  script_summary(english:"Checks file version of the affected files.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The Windows kernel drivers on the remote host are affected by multiple
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Windows host has the following vulnerabilities :

  - Multiple remote code execution vulnerabilities exist in
    the way the Windows kernel-mode driver parses OpenType
    and TrueType fonts. (CVE-2013-3128, CVE-2013-3894)

  - Multiple privilege escalation vulnerabilities exist in
    the Windows kernel-mode drivers. (CVE-2013-3879,
    CVE-2013-3880, CVE-2013-3880, CVE-2013-3888)

  - A privilege escalation vulnerability exists in
    the Windows USB drivers. (CVE-2013-3200)

An attacker who successfully exploited these vulnerabilities could read
arbitrary amounts of kernel memory or gain elevated privileges.

Note that the update was re-offered for Windows 7 and 2008 R2 as of
January 14, 2014.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-235/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-237/");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms13-081");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Windows XP, 2003, Vista,
2008, 7, 2008 R2, 8, Windows RT, and 2012."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Windows TrackPopupMenuEx Win32k NULL Page');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
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

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS13-081';

kbs = make_list('2847311', '2855844', '2862330', '2862335', '2863725', '2864202', '2868038', '2876284', '2883150', '2884256');
if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);
if (hotfix_check_sp_range(xp:'3', win2003:'2', vista:'2', win7:'1', win8:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

# Check if this is a virtual host
registry_init();
hcf_init = TRUE;
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
biosproductname = get_registry_value(handle:hklm, item:"HARDWARE\Description\System\BIOS\SystemProductName");
if (biosproductname) biosproductname = tolower(biosproductname);
RegCloseKey(handle:hklm);
close_registry(close:FALSE);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

vuln = 0;
########## KB2847311 ###########
#  Windows XP SP3,             #
#  Windows XP SP2 x64,         #
#  Windows 2003 SP2,           #
#  Windows Vista SP2,          #
#  Windows 7 SP1,              #
#  Windows Server 2008 R2      #
#  Windows Server 8            #
#  Windows Server 2012         #
################################
if (
  # Windows 8 / Windows Server 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"Atmfd.dll", version:"5.1.2.237", dir:"\system32", bulletin:bulletin, kb:'2847311') ||

  # Windows 7 and Windows Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Atmfd.dll", version:"5.1.2.238", dir:"\system32", bulletin:bulletin, kb:'2847311') ||

  # Vista / Windows 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Atmfd.dll", version:"5.1.2.236", dir:"\system32", bulletin:bulletin, kb:'2847311') ||

  # Windows 2003 / XP x64
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Atmfd.dll", version:"5.2.2.236", dir:"\system32", bulletin:bulletin, kb:'2847311') ||

  # Windows XP x86
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Atmfd.dll", version:"5.1.2.236", dir:"\system32", bulletin:bulletin, kb:'2847311')
) vuln++;

########## KB2855844 ###########
#  Windows Vista SP2,          #
#  Windows 7 SP1,              #
#  Windows Server 2008,        #
#  Windows Server 2008 R2      #
################################
if (
  # Windows 7 and Windows Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Fntcache.dll", version:"6.1.7601.22434", min_version:"6.1.7601.22000", dir:"\system32", bulletin:bulletin, kb:'2855844') ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Fntcache.dll", version:"6.1.7601.18245", min_version:"6.1.7600.18000", dir:"\system32", bulletin:bulletin, kb:'2855844') ||

  # Vista / Windows 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Fntcache.dll", version:"7.0.6002.23200", min_version:"7.0.6002.23000", dir:"\system32", bulletin:bulletin, kb:'2855844') ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Fntcache.dll", version:"7.0.6002.18923", min_version:"7.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:'2855844')
) vuln++;


########## KB2862330 ###########
#  Windows XP SP3,             #
#  Windows XP SP2 x64,         #
#  Windows 2003 SP2,           #
#  Windows Vista SP2,          #
#  Windows 7 SP1,              #
#  Windows Server 2008 R2      #
#  Windows Server 8            #
#  Windows Server 2012         #
################################
# Don't check for KB2862330 if the host is a virtual host
if (biosproductname && ('vmware' >!< biosproductname && 'virtual box' >!< biosproductname && 'vbox' >!< biosproductname && 'virtual machine' >!< biosproductname && 'seabios' >< biosproductname))
{
  if (
    # Windows 8 / Windows Server 2012
    hotfix_is_vulnerable(os:"6.2", sp:0, file:"Usbport.sys", version:"6.2.9200.20761", min_version:"6.2.9200.20000", dir:"\system32\drivers", bulletin:bulletin, kb:'2862330') ||
    hotfix_is_vulnerable(os:"6.2", sp:0, file:"Usbport.sys", version:"6.2.9200.16654", min_version:"6.2.9200.16000", dir:"\system32\drivers", bulletin:bulletin, kb:'2862330') ||

    # Windows 7 and Windows Server 2008 R2
    hotfix_is_vulnerable(os:"6.1", sp:1, file:"Usbport.sys", version:"6.1.7601.22526", min_version:"6.1.7601.22000", dir:"\system32\drivers", bulletin:bulletin, kb:'2862330') ||
    hotfix_is_vulnerable(os:"6.1", sp:1, file:"Usbport.sys", version:"6.1.7601.18328", min_version:"6.1.7600.18000", dir:"\system32\drivers", bulletin:bulletin, kb:'2862330') ||
  
    # Vista / Windows 2008
    hotfix_is_vulnerable(os:"6.0", sp:2, file:"Usbport.sys", version:"6.0.6002.23147", min_version:"6.0.6002.23000", dir:"\system32\drivers", bulletin:bulletin, kb:'2862330') ||
    hotfix_is_vulnerable(os:"6.0", sp:2, file:"Usbport.sys", version:"6.0.6002.18875", min_version:"6.0.6002.18000", dir:"\system32\drivers", bulletin:bulletin, kb:'2862330') ||
 
    # Windows 2003 / XP x64
    hotfix_is_vulnerable(os:"5.2", sp:2, file:"Usbport.sys", version:"5.2.3790.5203", dir:"\system32\drivers", bulletin:bulletin, kb:'2862330') ||

    # Windows XP x86
    hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Usbport.sys", version:"5.1.2600.6437", dir:"\system32\drivers", bulletin:bulletin, kb:'2862330')
  ) vuln++;
}

########## KB2862335 ###########
#  Windows XP SP3,             #
#  Windows XP SP2 x64,         #
#  Windows 2003 SP2,           #
#  Windows Vista SP2,          #
#  Windows 7 SP1,              #
#  Windows Server 2008 R2      #
#  Windows Server 8            #
#  Windows Server 2012         #
################################
if (
  # Windows 8 / Windows Server 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"Usbscan.sys", version:"6.2.9200.20763", min_version:"6.2.9200.20000", dir:"\system32\drivers", bulletin:bulletin, kb:'2862335') ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"Usbscan.sys", version:"6.2.9200.16656", min_version:"6.2.9200.16000", dir:"\system32\drivers", bulletin:bulletin, kb:'2862335') ||

  # Windows 7 and Windows Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Usbscan.sys", version:"6.1.7601.22374", min_version:"6.1.7601.22000", dir:"\system32\drivers", bulletin:bulletin, kb:'2862335') ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Usbscan.sys", version:"6.1.7601.18199", min_version:"6.1.7600.18000", dir:"\system32\drivers", bulletin:bulletin, kb:'2862335') ||

  # Vista / Windows 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Usbscan.sys", version:"6.0.6002.23150", min_version:"6.0.6002.23000", dir:"\system32\drivers", bulletin:bulletin, kb:'2862335') ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Usbscan.sys", version:"6.0.6002.18878", min_version:"6.0.6002.18000", dir:"\system32\drivers", bulletin:bulletin, kb:'2862335') ||

  # Windows 2003 / XP x64
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Usbscan.sys", version:"5.2.3790.5189",  dir:"\system32\drivers", bulletin:bulletin, kb:'2862335') ||

  # Windows XP x86
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Usbscan.sys", version:"5.1.2600.6418", dir:"\system32\drivers", bulletin:bulletin, kb:'2862335')
) vuln++;

########## KB2863725 ###########
#  Windows Server 8            #
#  Windows Server 2012         #
################################
if (
  # Windows 8 / Windows Server 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"Usbhub3.sys", version:"6.2.9200.20763", min_version:"6.2.9200.20000", dir:"\system32\drivers", bulletin:bulletin, kb:'2863725') ||

  hotfix_is_vulnerable(os:"6.2", sp:0, file:"Usbhub3.sys", version:"6.2.9200.16654", min_version:"6.2.9200.16000", dir:"\system32\drivers", bulletin:bulletin, kb:'2863725')
) vuln++;

########## KB2864202 ###########
#  Windows Vista SP2,          #
#  Windows 7 SP1,              #
#  Windows Server 2008 R2      #
#  Windows Server 8            #
#  Windows Server 2012         #
################################
if (
  # Windows 8 / Windows Server 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"Wdfres.dll", version:"6.2.9200.16384", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:'2864202') ||

  # Windows 7 and Windows Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Wdfres.dll", version:"6.2.9200.16384", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:'2864202') ||

  # Vista / Windows 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Wdfres.dll", version:"6.2.9200.16384", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:'2864202')
) vuln++;


########## KB2868038 ###########
#  Windows XP SP3,             #
#  Windows XP SP2 x64,         #
#  Windows 2003 SP2,           #
#  Windows Vista SP2,          #
#  Windows 7 SP1,              #
#  Windows Server 2008 R2      #
#  Windows Server 8            #
#  Windows Server 2012         #
################################
if (
  # Windows 8 / Windows Server 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"Usbcir.sys", version:"6.2.9200.20772", min_version:"6.2.9200.20000", dir:"\system32\drivers", bulletin:bulletin, kb:'2868038') ||
  hotfix_is_vulnerable(os:"6.2", sp:0, arch:"x86", file:"Usbcir.sys", version:"6.2.9200.16659", min_version:"6.2.9200.16000", dir:"\system32\drivers", bulletin:bulletin, kb:'2868038') ||
  hotfix_is_vulnerable(os:"6.2", sp:0, arch:"x64", file:"Usbcir.sys", version:"6.2.9200.16658", min_version:"6.2.9200.16000", dir:"\system32\drivers", bulletin:bulletin, kb:'2868038') ||

  # Windows 7 and Windows Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Usbcir.sys", version:"6.1.7601.22382", min_version:"6.1.7601.22000", dir:"\system32\drivers", bulletin:bulletin, kb:'2868038') ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Usbcir.sys", version:"6.1.7601.18208", min_version:"6.1.7600.16000", dir:"\system32\drivers", bulletin:bulletin, kb:'2868038') ||

  # Vista / Windows 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Usbcir.sys", version:"6.0.6002.23160", min_version:"6.0.6002.23000", dir:"\system32\drivers", bulletin:bulletin, kb:'2868038') ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Usbcir.sys", version:"6.0.6002.18887", min_version:"6.0.6002.18000", dir:"\system32\drivers", bulletin:bulletin, kb:'2868038') ||

  # Windows 2003 / XP x64
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Usbaudio.sys", version:"5.2.3790.5198",  dir:"\system32\drivers", bulletin:bulletin, kb:'2868038') ||

  # Windows XP x86
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Usbaudio.sys", version:"5.1.2600.6425", dir:"\system32\drivers", bulletin:bulletin, kb:'2868038')
) vuln++;

########## KB2876284 ###########
#  Windows Vista SP2,          #
#  Windows 7 SP1,              #
#  Windows Server 2008 R2      #
################################
if (
  # Windows 7 and Windows Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Dxgkrnl.sys", version:"6.1.7601.22410", min_version:"6.1.7601.21000", dir:"\system32\drivers", bulletin:bulletin, kb:'2876284') ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Dxgkrnl.sys", version:"6.1.7601.18228", min_version:"6.1.7600.17000", dir:"\system32\drivers", bulletin:bulletin, kb:'2876284') ||

  # Vista / Windows 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Dxgkrnl.sys", version:"6.0.6002.23181", min_version:"6.0.6002.22000", dir:"\system32\drivers", bulletin:bulletin, kb:'2876284') ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Dxgkrnl.sys", version:"7.0.6002.18908", min_version:"6.0.6002.18000", dir:"\system32\drivers", bulletin:bulletin, kb:'2876284')
) vuln++;


########## KB2883150 ###########
#  Windows XP SP3,             #
#  Windows XP SP2 x64,         #
#  Windows 2003 SP2,           #
#  Windows Vista SP2,          #
#  Windows 7 SP1,              #
#  Windows Server 2008 R2      #
#  Windows Server 8            #
#  Windows Server 2012         #
################################
if (
  # Windows 8 / Windows Server 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"Win32k.sys", version:"6.2.9200.20807", min_version:"6.2.9200.20000", dir:"\system32", bulletin:bulletin, kb:'2883150') ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"Win32k.sys", version:"6.2.9200.16699", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:'2883150') ||

  # Windows 7 and Windows Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Win32k.sys", version:"6.1.7601.22435", min_version:"6.1.7601.22000", dir:"\system32", bulletin:bulletin, kb:'2883150') ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Win32k.sys", version:"6.1.7601.18246", min_version:"6.1.7600.18000", dir:"\system32", bulletin:bulletin, kb:'2883150') ||

  # Vista / Windows 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Win32k.sys", version:"6.0.6002.23204", min_version:"6.0.6002.23000", dir:"\system32", bulletin:bulletin, kb:'2883150') ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Win32k.sys", version:"6.0.6002.18927", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:'2883150') ||

  # Windows 2003 / XP x64
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Win32k.sys", version:"5.2.3790.5216",  dir:"\system32", bulletin:bulletin, kb:'2883150') ||

  # Windows XP x86
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Win32k.sys", version:"5.1.2600.6442", dir:"\system32", bulletin:bulletin, kb:'2883150')
) vuln++;

########## KB2884256 ###########
#  Windows XP SP3,             #
#  Windows XP SP2 x64,         #
#  Windows 2003 SP2,           #
#  Windows Vista SP2,          #
#  Windows 7 SP1,              #
#  Windows Server 2008 R2      #
#  Windows Server 8            #
#  Windows Server 2012         #
################################
if (
  # Windows 8 / Windows Server 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"Usbser.sys", version:"6.2.9200.20810", min_version:"6.2.9200.20000", dir:"\system32\drivers", bulletin:bulletin, kb:'2884256') ||
  hotfix_is_vulnerable(os:"6.2", sp:0, arch:"x64", file:"Usbser.sys", version:"6.2.9200.16702", min_version:"6.2.9200.16000", dir:"\system32\drivers", bulletin:bulletin, kb:'2884256') ||
  hotfix_is_vulnerable(os:"6.2", sp:0, arch:"x86", file:"Usbser.sys", version:"6.2.9200.16697", min_version:"6.2.9200.16000", dir:"\system32\drivers", bulletin:bulletin, kb:'2884256') ||

  # Windows 7 and Windows Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Usbser.sys", version:"6.1.7601.22436", min_version:"6.1.7601.22000", dir:"\system32\drivers", bulletin:bulletin, kb:'2884256') ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Usbser.sys", version:"6.1.7601.18247", min_version:"6.1.7600.18000", dir:"\system32\drivers", bulletin:bulletin, kb:'2884256') ||

  # Vista / Windows 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Usbser.sys", version:"6.0.6002.23204", min_version:"6.0.6002.23000", dir:"\system32\drivers", bulletin:bulletin, kb:'2884256') ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Usbser.sys", version:"6.0.6002.18927", min_version:"6.0.6002.18000", dir:"\system32\drivers", bulletin:bulletin, kb:'2884256') ||

  # Windows 2003 / XP
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Usbser.sys", version:"5.2.3790.5216",  dir:"\system32\drivers", bulletin:bulletin, kb:'2884256') ||

  # Windows XP x86
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Usbser.sys", version:"5.1.2600.6442", dir:"\system32\drivers", bulletin:bulletin, kb:'2884256')
) vuln++;

if (vuln > 0)
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
