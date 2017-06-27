#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(67214);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/04/23 21:44:06 $");

  script_cve_id("CVE-2013-3127");
  script_bugtraq_id(60980);
  script_osvdb_id(94986);
  script_xref(name:"MSFT", value:"MS13-057");
  script_xref(name:"IAVB", value:"2013-B-0072");

  script_name(english:"MS13-057: Vulnerability in Windows Media Format Runtime Could Allow Remote Code Execution (2847883)");
  script_summary(english:"Checks version of Wmv9vcm.dll, Wmvdmod.dll, and Wmvdecod.dll");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is potentially affected by a remote code
execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is potentially affected by a vulnerability that
could allow remote code execution if a user opens a malicious media
file.  Successful exploitation of this vulnerability could allow an
attacker to gain the same user rights as the local user.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-168/");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms13-057");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows XP, 2003, Vista, 7,
2008, 2008 R2, 8, and 2012.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");

  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, 'Host/patch_management_checks');

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS13-057';

kbs = make_list(
'2847883',
'2845142',
'2834902',
'2834904',
'2834903',
#'2834905',
'2803821'
);
if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
winver = get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(xp:'3', win2003:'2', vista:'2', win7:'1', win8:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);


vuln = 0;

# wmv9vcm.dll (codec) on Windows XP, Windows Server 2003, Windows Vista, and Windows Server 2008 #
########## KB2845142 ###########
#  Windows XP SP3,             #
#  Windows XP SP2 x64,         #
#  Windows 2003 SP2,           #
#  Windows Vista SP2,          #
#  Windows Server 2008 SP2,    #
################################
kb = '2845142';
if (
  # Vista / Windows 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, arch:"x86", file:"Wmv9vcm.dll", version:"9.0.1.3073", min_version:"9.0.1.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, arch:"x64", file:"Wmv9vcm.dll", version:"9.0.1.3073", min_version:"9.0.1.0", dir:"\SysWOW64", bulletin:bulletin, kb:kb) ||

  # Windows 2003 / XP x64
  hotfix_is_vulnerable(os:"5.2", sp:2, arch:"x86", file:"Wmv9vcm.dll", version:"9.0.1.3073", min_version:"9.0.1.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.2", sp:2, arch:"x64", file:"Wmv9vcm.dll", version:"9.0.1.3073", min_version:"9.0.1.0", dir:"\SysWOW64", bulletin:bulletin, kb:kb) ||

  # Windows XP x86
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Wmv9vcm.dll", version:"9.0.1.3073", min_version:"9.0.1.0", dir:"\system32", bulletin:bulletin, kb:kb)
) vuln++;

# Windows Media Format Runtime 9.5 x64 (wmvdmod.dll) on Windows XP and Windows Server 2003 #
########## KB2834902 ###########
#  Windows XP SP3,             #
#  Windows XP SP2 x64,         #
#  Windows 2003 SP2,           #
################################
kb = '2834902';
if (
  # Windows 2003 / XP x64
  hotfix_is_vulnerable(os:"5.2", sp:2, arch:"x64", file:"Wmvdmod.dll", version:"10.0.0.3823", min_version:"10.0.0.3000", dir:"\SysWOW64", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.2", sp:2, arch:"x86", file:"Wmvdmod.dll", version:"10.0.0.3823", min_version:"10.0.0.3000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows XP x86
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Wmvdmod.dll", version:"10.0.0.3706", min_version:"10.0.0.3000", dir:"\system32", bulletin:bulletin, kb:kb)
) vuln++;

# Windows Media Format Runtime 9.5 and 11 (wmvdecod.dll) on Windows XP and Windows Server 2003 #
########## KB2834904 ###########
#  Windows XP SP3,             #
#  Windows XP SP2 x64,         #
#  Windows 2003 SP2,           #
################################
kb = '2834904';
if (
  # Windows 2003 / XP x64
  hotfix_is_vulnerable(os:"5.2", sp:2, arch:"x64", file:"Wmvdecod.dll", version:"11.0.5721.5287", min_version:"11.0.5721.0", dir:"\SysWOW64", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.2", sp:2, arch:"x86", file:"Wmvdecod.dll", version:"11.0.5721.5287", min_version:"11.0.5721.0", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows XP x86
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Wmvdecod.dll", version:"11.0.5721.5287", min_version:"11.0.5721.0", dir:"\system32", bulletin:bulletin, kb:kb)
) vuln++;

# Windows Media Format Runtime 9.5 (wmvdmod.dll) on Windows XP #
########## KB2834903 ###########
#  Windows XP SP3,             #
################################
kb = '2834903';
if (
  # Windows XP x86
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Wmvdmod.dll", version:"10.0.0.4082", min_version:"10.0.0.3802", dir:"\system32", bulletin:bulletin, kb:kb)
) vuln++;

# # Windows Media Format Runtime 9.5 (wmvdmod.dll) on Windows XP Media Center Edition #
# ########## KB2834905 ###########
# #  Windows XP SP3,             #
# ################################
# kb = '2834905';
# if (
#   # Windows XP x86
#   hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Wmvdmod.dll", version:"10.0.0.4375", dir:"\system32", bulletin:bulletin, kb:kb)
# ) vuln++;

# Windows Media Format Runtime 9 and 9.5 (wmvdmod.dll), and for Windows Media Player 11 and 12 #
########## KB2803821 ###########
#  Windows XP SP3,             #
#  Windows XP SP2 x64,         #
#  Windows 2003 SP2,           #
#  Windows Vista SP2,          #
#  Windows 7,                  #
#  Windows Server 2008 SP2,    #
#  Windows Server 2008 R2      #
#  Windows Server 8            #
#  Windows Server 2012         #
################################
kb = '2803821';
if (
  # Windows 8 / Windows Server 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"Wmvdecod.dll", version:"6.2.9200.20708", min_version:"6.2.9200.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"Wmvdecod.dll", version:"6.2.9200.16604", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 7 and Windows Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Wmvdecod.dll", version:"6.1.7601.22402", min_version:"6.1.7601.22000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Wmvdecod.dll", version:"6.1.7601.18221", min_version:"6.1.7600.18000", dir:"\system32", bulletin:bulletin, kb:kb) ||

#  # Vista / Windows 2008
#  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Wmvdecod.dll", version:"6.0.6002.23182", min_version:"6.0.6002.23000", dir:"\system32", bulletin:bulletin, kb:kb) ||
#  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Wmvdecod.dll", version:"6.0.6002.18909", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 2003 / XP x64
  hotfix_is_vulnerable(os:"5.2", sp:2, arch:"x86", file:"Wmvdmod.dll", version:"10.0.0.4010", min_version:"10.0.0.3900", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.2", sp:2, arch:"x64", file:"Wmvdmod.dll", version:"10.0.0.4010", min_version:"10.0.0.3900",  dir:"\SysWOW64", bulletin:bulletin, kb:kb) ||

  # Windows XP x86
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Wmvdmod.dll", version:"9.0.0.4512", min_version:"9.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb)
) vuln++;
# Vista / Windows 2008
if ('6.0' >< winver)
{
  arch = get_kb_item_or_exit('SMB/ARCH');
  sp = get_kb_item_or_exit('SMB/CSDVersion');
  sp = ereg_replace(pattern:'.*Service Pack ([0-9]).*', string:sp, replace:"\1");
  sp = int(sp);
  if (sp == 2)
  {
    if ('x64' >< arch)
      dir = hotfix_get_systemroot() + "\SysWOW64";
    else
      dir = hotfix_get_systemroot() + "\system32";

    file = dir + "\Wmvdecod.dll";
    ver = hotfix_get_fversion(path:file);
    if (ver['error'] == HCF_OK)
    {
      ver = ver['value'];
      if (int(ver[0]) == 11 && int(ver[1]) == 0 &&
        (
          int(ver[2]) == 6001 ||
          (
            int(ver[2]) == 6002 && int(ver[3]) <= 18005
          )
        )
      )
      {
        version = join(ver, sep:'.');

        hotfix_add_report(
         '- ' + file + ' has not been patched\n' +
         '    Remote version : ' + version + '\n' +
         '    Should be : 6.0.6002.18909\n', bulletin:bulletin, kb:kb
       );
       smb_hf_add(os:'6.0', sp:2, file:file, version:version, bulletin:bulletin, kb:kb);
       vuln++;
      }
    }
    else
    {
      if (hotfix_is_vulnerable(os:"6.0", sp:2, file:"Wmvdecod.dll", version:"6.0.6002.23182", min_version:"6.0.6002.23000", dir:"\system32", bulletin:bulletin, kb:kb) ||
          hotfix_is_vulnerable(os:"6.0", sp:2, file:"Wmvdecod.dll", version:"6.0.6002.18909", min_version:"6.0.6002.18835", dir:"\system32", bulletin:bulletin, kb:kb)) vuln++;
    }
  }
}


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
