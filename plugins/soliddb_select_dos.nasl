#
#  (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57824);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/05/29 04:24:09 $");

  script_cve_id("CVE-2011-4890");
  script_bugtraq_id(51629);
  script_osvdb_id(78550);

  script_name(english:"IBM solidDB < 7.0 Fix Pack 1 / 6.5.0.8 Interim Fix 5 Denial of Service");
  script_summary(english:"Checks version of solid.exe");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote database server is affected by a denial of service
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its version number, the solidDB install on the remote
host is affected by a denial of service vulnerability due to a flaw in
the way the application handles 'SELECT' statements containing a
'rownum' condition with a subquery. 

A remote, unauthenticated attacker can leverage this issue to cause
the application to crash."
  );
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IC79861");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg27021052#if5");
  script_set_attribute(attribute:"see_also", value:"http://xforce.iss.net/xforce/xfdb/72651");
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to IBM solidDB 7.0 Fix Pack 1 / 6.5.0.8 Interim Fix 5 or 
later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/12/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:soliddb");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

  script_dependencies("soliddb_installed.nasl", "soliddb_detect.nasl");
  script_require_keys("SMB/solidDB/installed");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

get_kb_item_or_exit('SMB/solidDB/installed');

installs = get_kb_list('SMB/solidDB/*/path');
if (isnull(installs)) exit(1, 'The SMB/solidDB/*/path KB list is missing.');

if (report_paranoia < 2) get_kb_item_or_exit('Services/soliddb');

vuln = 0;
report = '';
foreach item (keys(installs))
{
  version = item - 'SMB/solidDB/';
  version = version - '/path';

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  if (ver[0] == 6)
    fix = '6.5.0.8 Interim Fix 5';
  else 
    fix = '7.0 Fix Pack 1';

  timestamp = get_kb_item('SMB/solidDB/' + version + '/timestamp');
  if (ver[0] == 6 && isnull(timestamp)) continue;

  if (
    (
      (ver[0] == 6 && ver[1] == 5  && ver[2] == 0 && ver[3] < 9) &&
      timestamp < 1326400061
    ) ||
    (ver[0] == 7 && ver[1] == 0 && ver[2] == 0 && ver[3] < 1)
  )
  {
    vuln++;

    report += 
      '\n  Path              : ' + installs[item] + 
      '\n  Installed version : ' + version + 
      '\n  Fixed version     : ' + fix + '\n';
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
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(port:get_kb_item("SMB/transport"));
  exit(0);
}
else exit(0, 'No vulnerable installs of solidDB were detected on the remote host.');
