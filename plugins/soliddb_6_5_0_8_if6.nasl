#
#  (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58106);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/05/29 04:24:09 $");

  script_cve_id("CVE-2012-0200");
  script_bugtraq_id(52111);
  script_osvdb_id(79010);

  script_name(english:"IBM solidDB 6.5 < 6.5.0.8 Interim Fix 6 Redundant WHERE Clause Select Statement Parsing Remote DoS");
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
redundant WHERE condition."
  );
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IC81244");
  script_set_attribute(attribute:"see_also", value:"http://www.ibm.com/support/docview.wss?uid=swg27021052");
  script_set_attribute(
    attribute:"solution",
    value:"Update to solidDB 6.5.0.8 Interim Fix 6 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/02/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/23");

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

get_kb_item_or_exit('SMB/Registry/Enumerated');

get_kb_item_or_exit('SMB/solidDB/installed');
installs = get_kb_list('SMB/solidDB/*/path');
if (isnull(installs)) exit(1, 'The SMB/solidDB/*/path KB list is missing.');

if (report_paranoia < 2) get_kb_item_or_exit('Services/soliddb');

fix = '6.5.0.8 Interim Fix 6';

vuln = 0;
report = '';
foreach item (keys(installs))
{
  version = item - 'SMB/solidDB/';
  version = version - '/path';
  path = installs[item];

  if (version == 'Unknown')
    exit(1, "The version of solidDB installed in "+path+" is unknown.");

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  timestamp = get_kb_item('SMB/solidDB/' + version + '/timestamp');

  if (
    isnull(timestamp) && 
    (ver[0] == 6 && ver[1] == 5  && ver[2] == 0 && ver[3] == 8)
  ) exit(1, "Failed to determine the timestamp for the version of solidDB installed in "+path+".");

  if (
    (ver[0] == 6 && ver[1] == 5  && ver[2] == 0 && ver[3] < 8) ||
    (
      (ver[0] == 6 && ver[1] == 5  && ver[2] == 0 && ver[3] == 8) &&
      timestamp < 1328646501
    )
  )
  {
    vuln++;

    report += 
      '\n  Path              : ' + path +
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
    security_warning(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_warning(port:get_kb_item("SMB/transport"));
  exit(0);
}
exit(0, 'No vulnerable installs of solidDB were detected on the remote host.');
