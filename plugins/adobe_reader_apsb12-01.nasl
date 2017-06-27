#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57484);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/11/11 19:58:28 $");

  script_cve_id(
    "CVE-2011-2462",
    "CVE-2011-4369",
    "CVE-2011-4370",
    "CVE-2011-4371",
    "CVE-2011-4372",
    "CVE-2011-4373"
  );
  script_bugtraq_id(50922, 51092, 51348, 51351, 51349, 51350);
  script_osvdb_id(77529, 78026, 78245, 78246, 78247, 78248);

  script_name(english:"Adobe Reader < 10.1.2 / 9.5 Multiple Vulnerabilities (APSB12-01)");
  script_summary(english:"Checks version of Adobe Reader");

  script_set_attribute(attribute:"synopsis",value:
"The version of Adobe Reader on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description",value:
"The version of Adobe Reader installed on the remote host is earlier
than 10.1.2 / 9.5, and therefore affected by multiple memory
corruption vulnerabilities.  An attacker could exploit these issues by
tricking a user into opening a maliciously crafted Reader file,
resulting in arbitrary code execution. 

Adobe Reader 10.1.2 is the first 10.x release to include fixes for
CVE-2011-2462 and CVE-2011-4369.  These were previously fixed for 9.x
releases in 9.4.7 (APSB11-30)."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-021");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/521538/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/advisories/apsa11-04.html");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb11-30.html");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb12-01.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Adobe Reader 9.5 / 10.1.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Reader U3D Memory Corruption Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/12/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat_reader");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:'Windows');
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies('adobe_reader_installed.nasl');
  script_require_keys('SMB/Acroread/Version');
  exit(0);
}

#

include('global_settings.inc');

info =  '';
info2 = '';
vuln = 0;
vers = get_kb_list('SMB/Acroread/Version');
if (isnull(vers)) exit(0, 'The "SMB/Acroread/Version" KB list is missing.');

foreach version (vers)
{
  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  path = get_kb_item('SMB/Acroread/'+version+'/Path');
  if (isnull(path)) path = 'n/a';

  verui = get_kb_item('SMB/Acroread/'+version+'/Version_UI');
  if (isnull(verui)) verui = version;

  # Adobe says versions 9.4.7 and earlier are affected, but recommends upgrading
  # to 9.5 (presumably 9.4.8 and 9.4.9 don't exist or aren't publicly available)
  if ( 
    (ver[0] == 9 && ver[1]  < 4) ||
    (ver[0] == 9 && ver[1] == 4 && ver[2] <= 7) ||
    (ver[0] == 10 && ver[1] < 1) ||
    (ver[0] == 10 && ver[1] == 1 && ver[2] < 2)
  )
  {
    vuln++;
    info += '\n  Path              : '+path+
            '\n  Installed version : '+verui+
            '\n  Fixed version     : 9.5 / 10.1.2\n';
  }
  else
    info2 += " and " + verui;
}

if (info)
{
  if (report_verbosity > 0)
  {
    if (vuln > 1) s = "s of Adobe Reader are";
    else s = " of Adobe Reader is";

    report =
      '\nThe following vulnerable instance'+s+' installed on the'+
      '\nremote host :\n'+
      info;
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));

  exit(0);
}

if (info2) 
{
  info2 -= " and ";
  if (" and " >< info2) be = "are";
  else be = "is";

  exit(0, "The host is not affected since Adobe Reader "+info2+" "+be+" installed.");
}
else exit(1, "Unexpected error - 'info2' is empty.");
