#
#  (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(53812);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/10/07 15:36:48 $");

  script_cve_id("CVE-2011-1208");
  script_bugtraq_id(47584);
  script_osvdb_id(72700);
  script_xref(name:"TRA", value:"TRA-2011-03");
  script_xref(name:"Secunia", value:"44380");

  script_name(english:"IBM solidDB < 4.5.182 / 6.0.1069 / 6.3.49 / 6.5.0.4 Denial of Service");
  script_summary(english:"Checks version of solid.exe"); 
 
  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by two denial of service
vulnerabilities." );
  script_set_attribute(attribute:"description", value:

"According to its version number, the solidDB install on the remote
host is affected by two denial of service vulnerabilities due to a
flaw in the way the application handles the 'rpc_test_svc_readwrite'
and and 'rpc_test_svc_done'procesure commands.  

A remote unauthenticated attacker can leverage these issues to cause
the application to de-reference a NULL pointer and subsequently
crash.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2011-03");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-142/");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21496106");
  script_set_attribute(attribute:"solution", value:"Upgrade to IBM solidDB 4.5.182, 6.0.1069, 6.3 Fix Pack 8, 6.5 Fix Pack 4, or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/04/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/05");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:soliddb");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_dependencies("soliddb_installed.nasl", "soliddb_detect.nasl");
  script_require_keys("SMB/solidDB/installed");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

if (report_paranoia < 2) get_kb_item_or_exit('Services/soliddb');

get_kb_item_or_exit('SMB/Registry/Enumerated');

installs = get_kb_list('SMB/solidDB/*/path');
if (isnull(installs)) exit(1, 'The SMB/solidDB/*/path KB list is missing.');

vuln = 0;
report = '';
foreach item (keys(installs))
{
  version = item - 'SMB/solidDB/';
  version = version - '/path';
  fix = NULL;
  if (version =~ '^([0-3]\\.|4\\.[0-5]0\\.)') fix = '4.50.0.182';
  else if (version =~ '^6\\.0\\.') fix = '6.0.0.1069';
  else if (version =~ '^6\\.30\\.') fix = '6.30.0.49';
  else if (version =~ '^6\\.5\\.') fix = '6.5.0.4';

  if (fix)
  {
    if (ver_compare(ver:version, fix:fix) == -1)
    {
      vuln++;

      report += 
        '\n  Path              : ' + installs[item] + 
        '\n  Installed version : ' + version + 
        '\n  Fixed version     : ' + fix + '\n';
    }
  }
}

if (report)
{
  if (report_verbosity > 0)
  {
    if (vuln > 1) s = 's of solidDB were found ';
    else s = ' of solidDB was found ';
    report =
      '\n  The following vulnerable install' + s + 'on the' +
      '\n  remote host :' +
      '\n' +
      report;
    security_warning(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_warning(port:get_kb_item("SMB/transport"));
  exit(0);
}
exit(0, 'No vulnerable installs of solidDB were detected on the remote host.');
