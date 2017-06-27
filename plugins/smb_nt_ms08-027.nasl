#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(32311);
 script_version("$Revision: 1.29 $");
 script_cvs_date("$Date: 2016/06/30 19:55:38 $");

 script_cve_id("CVE-2008-0119");
 script_bugtraq_id(29158);
 script_osvdb_id(45033);
 script_xref(name:"MSFT", value:"MS08-027");

 script_name(english:"MS08-027: Vulnerability in Microsoft Publisher Could Allow Remote Code Execution (951208)");
 script_summary(english:"Determines the version of MSPUB.exe");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Microsoft
Publisher.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft Publisher that is
subject to a flaw that could allow arbitrary code to be run.

An attacker may use this to execute arbitrary code on this host.

To succeed, the attacker would have to send a rogue file to a user of
the remote computer and have it open it.  Then a bug in the font parsing
handler would result in code execution.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms08-027");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Publisher 2000, XP, 2003
and 2007.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(94);

 script_set_attribute(attribute:"vuln_publication_date", value:"2008/05/13");
 script_set_attribute(attribute:"patch_publication_date", value:"2008/05/13");
 script_set_attribute(attribute:"plugin_publication_date", value:"2008/05/13");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:publisher");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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
include("audit.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS08-027';
kbs = make_list("950114", "950129", "950213", "950682");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

port = kb_smb_transport();
if (!is_accessible_share()) exit(0);

vuln = 0;
list = get_kb_list("SMB/Office/Publisher/*/ProductPath");
if (!isnull(list))
{
  foreach item (keys(list))
  {
    v = item - 'SMB/Office/Publisher/' - '/ProductPath';
    if(ereg(pattern:"^9\..*", string:v))
    {
      # Publisher 2000 - fixed in 9.0.8932.0 ? 9.00.00.8931
      sub =  ereg_replace(pattern:"^9\.00?\.00?\.([0-9]*)$", string:v, replace:"\1");
      if(sub != v && int(sub) < 8932 ) {
        vuln++;
        kb = '950682';
        hotfix_add_report(bulletin:bulletin, kb:kb);
      }
    }
    else if(ereg(pattern:"^10\..*", string:v))
    {
      # Publisher XP - fixed in 10.0.6842.0
      middle =  ereg_replace(pattern:"^10\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
      if(middle != v && int(middle) < 6842) {
        vuln++;
        kb = '950129';
        hotfix_add_report(bulletin:bulletin, kb:kb);
      }
    }
    else if(ereg(pattern:"^11\..*", string:v))
    {
      # Publisher 2003 - fixed in 11.0.8212.0
      middle =  ereg_replace(pattern:"^11\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
      if(middle != v && int(middle) < 8212) {
        vuln++;
        kb = '950213';
        hotfix_add_report(bulletin:bulletin, kb:kb);
      }
    }
    else if(ereg(pattern:"^12\..*", string:v))
    {
      # Publisher 2007 - fixed in 12.0.6308.5000
      middle =  ereg_replace(pattern:"^12\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
      if(middle != v && int(middle) < 6308) {
        vuln++;
        kb = '950114';
        hotfix_add_report(bulletin:bulletin, kb:kb);
      }
    }
  }
}

vers = hotfix_check_office_version();
if (!isnull(vers))
{
  foreach ver (keys(vers))
  {
    path = hotfix_get_officeprogramfilesdir(officever:ver);
    if (path)
    {
      if (
        ("9.0" >< ver && hotfix_check_fversion(file:"Ptxt9.dll", path:path +"\Microsoft Office\Office", version:"9.0.0.8929", min_version:"9.0.0.0", bulletin:bulletin, kb:'950682') == HCF_OLDER) ||
        ("10.0" >< ver && hotfix_check_fversion(file:"Ptxt9.dll", path:path +"\Microsoft Office\Office10", version:"10.0.6842.0", bulletin:bulletin, kb:'950129') == HCF_OLDER) ||
        ("11.0" >< ver && hotfix_check_fversion(file:"Ptxt9.dll", path:path +"\Microsoft Office\Office11", version:"11.0.8212.0", bulletin:bulletin, kb:'950213') == HCF_OLDER) ||
        ("12.0" >< ver && hotfix_check_fversion(file:"Ptxt9.dll", path:path +"\Microsoft Office\Office12", version:"12.0.6300.5000", bulletin:bulletin, kb:'950114') == HCF_OLDER)
      )
      {
        vuln++;
      }
    }
  }
  hotfix_check_fversion_end();
}
if (vuln)
{
  set_kb_item(name:"SMB/Missing/MS08-027", value:TRUE);
  hotfix_security_hole();
  exit(0);
}
else audit(AUDIT_HOST_NOT, 'affected');
