#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(54606);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/09/26 16:33:57 $");

  script_cve_id("CVE-2011-0614", "CVE-2011-0615");
  script_bugtraq_id(47838, 47841);
  script_osvdb_id(72326, 72327);
  script_xref(name:"Secunia", value:"44588");

  script_name(english:"Adobe Audition < CS5.5 Multiple SES Session File Processing Overflows (APSB11-10)");
  script_summary(english:"Checks version of Adobe Audition");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed that is affected
by multiple buffer overflow vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the Adobe Audition install on the
remote host is potentially affected by multiple buffer overflows when
handling specially crafted Audition Session (.ses) files. 

By tricking a user into opening a specially crafted .ses file, an
unauthenticated, remote attacker may be able to leverage these issues
to execute arbitrary code subject to the privileges of the user
running the application.");

  script_set_attribute(attribute:"see_also", value:"http://www.zeroscience.mk/en/vulnerabilities/ZSL-2011-5012.php");
  script_set_attribute(attribute:"see_also", value:"http://www.coresecurity.com/content/Adobe-Audition-malformed-SES-file");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2011/May/110");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb11-10.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Adobe Audition CS5.5 (4.0) or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/05/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/20");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:audition");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("adobe_audition_installed.nasl");
  script_require_keys("SMB/Adobe_Audition/installed");

  exit(0);
}

include('global_settings.inc');
include('misc_func.inc');

installs = get_kb_list('SMB/Adobe_Audition/*/Path');
if (isnull(installs)) exit(1, 'The SMB/Adobe_Audition/*/path KB list is missing.');

vuln = 0;
report = '';
foreach item (keys(installs))
{
  version = item - 'SMB/Adobe_Audition/';
  version = version - '/Path';
  if (version == 'Unknown') continue;

  verui = get_kb_item('SMB/Adobe_Audition/'+version+'/Version_UI');
  fix = '4.0.0.0';

  if (ver_compare(ver:version, fix:fix) == -1)
  {
    vuln++;

    report +=
      '\n  Path              : ' + installs[item] +
      '\n  Installed version : ' + verui +
      '\n  Fixed version     : CS5.5 (4.0)\n';
  }
}

if (report)
{
  if (report_verbosity > 0)
  {
    if (vuln > 1) s = 's of Adobe Audition were found ';
    else s = ' of Adobe Audition was found ';

    report = 
      '\n  The following vulnerable install' + s + 'on the' +
      '\n  remote host :' +
      '\n' +
      report;
    security_hole(port:get_kb_item('SMB/transport'), extra:report);
  }
  else security_hole(port:get_kb_item('SMB/transport'));
  exit(0);
}
exit(0, 'No vulnerable installs of Adobe Audition were detected on the remote host.');
