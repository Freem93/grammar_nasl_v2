#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(49274);
 script_version("$Revision: 1.7 $");
 script_cvs_date("$Date: 2012/09/14 15:15:51 $");

 script_cve_id("CVE-2010-3213");
 script_bugtraq_id(41462);
 script_osvdb_id(67119);
 script_xref(name:"EDB-ID", value:"14285");
 script_xref(name:"Secunia", value:"41421");

 script_name(english:"MS KB2401593: Microsoft Outlook Web Access (OWA) CSRF");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a cross-site request forgery
issue." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Outlook Web Access (OWA) for
Exchange Server that is affected by a cross-site request forgery
vulnerability.  By tricking an authenticated user to click on a link
to a specially crafted web page, it may be possible for an attacker to
perform unauthorized actions on behalf of the authenticated user. 
" );
 script_set_attribute(attribute:"see_also", value:"http://sites.google.com/site/tentacoloviola/pwning-corporate-webmails" );
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/advisory/2401593" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to either Microsoft Exchange Server 2007 Service Pack 3 /
Exchange Server 2010 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2010/07/08"); 
 script_set_attribute(attribute:"patch_publication_date", value:"2010/06/20"); # 2007 sp3 release date?
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/17");
 script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:microsoft:outlook_web_access");
 script_end_attributes();

 script_summary(english:"Determines the OWA version of Exchange");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2010-2012 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated","SMB/Exchange/Version");
 script_require_ports(139, 445);
 exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("SMB/Exchange/Version");

# Flag exchange 2003 SP2 , 2007 SP1, SP2.

# 2003
if(version == 65)
{
  path2003 = get_kb_item("SMB/Exchange/Path") + "\exchweb\bin\auth";
  sp = get_kb_item("SMB/Exchange/SP");

  if(sp && sp == 2)
  { 
    if (hotfix_check_fversion(path:path2003, file:"Owaauth.dll", version:"8.3.83.0", min_version:"6.5.7638.0") == HCF_OLDER) 
     hotfix_security_warning();

    hotfix_check_fversion_end();
    exit(0);
  }
  else exit(0, "The host is not affected since Microsoft Exchange 2003 SP 2 is not installed.");
}
# 2007
else if (version == 80)
{
  path2007 = get_kb_item("SMB/Exchange/Path") + "\ClientAccess\Owa\auth";
  sp = get_kb_item("SMB/Exchange/SP");

  # SP1 and SP2 are affected.
  if(sp && (sp == 1 || sp == 2))
  {
    if (hotfix_check_fversion(path:path2007, file:"owaauth.dll", version:"8.3.83.0", min_version:"8.1.0.0") == HCF_OLDER)
      hotfix_security_warning();

    hotfix_check_fversion_end();
    exit(0);
  }
  else
    exit (0, "The host is not affected since Microsoft Exchange 2007 SP 1 or 2 is not installed.");
}
else exit(0, "The host is not affected.");
