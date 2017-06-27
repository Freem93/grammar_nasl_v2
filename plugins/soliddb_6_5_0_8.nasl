#
#  (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58105);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/05/29 04:24:09 $");

  script_cve_id("CVE-2010-4055", "CVE-2010-4056", "CVE-2010-4057");
  script_bugtraq_id(44158);
  script_osvdb_id(68936, 68937, 68938);
  script_xref(name:"EDB-ID", value:"15261");

  script_name(english:"IBM solidDB 6.5 < 6.5.0.8 Multiple Denial of Service Vulnerabilities");
  script_summary(english:"Checks version of solid.exe");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote database server is affected by multiple denial of service
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote database system is affected by multiple denial of service
vulnerabilities :

  -  Sending packets with many integer fields can trigger 
     several recursive calls of a certain function causing 
     an excessive amount of stack memory consumption. 
     (CVE-2010-4055, IC80074)

  -  Upon receiving a packet containing only a single 
     integer field, a NULL pointer dereference can occur 
     causing a daemon crash. (CVE-2010-4056, IC80075)

  -  When receiving a packet with many different integer 
     fields containing two different values, an invalid 
     memory access and daemon crash can occur. 
     (CVE-2010-4057, IC80076)"
  );

  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg27021052#fp8");
  script_set_attribute(attribute:"solution", value:"Update to solidDB 6.5.0.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/10/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
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

fix = '6.5.0.8';

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

  if (ver[0] == 6 && ver[1] == 5  && ver[2] == 0 && ver[3] < 8)
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
