#
#  (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66351);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/05/29 04:24:09 $");

  script_cve_id("CVE-2013-3031");
  script_bugtraq_id(59637);
  script_osvdb_id(92955);

  script_name(english:"IBM solidDB Stored Procedure Call Remote Denial of Service");
  script_summary(english:"Checks version of solidDB");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has a database server installed that is affected by a
remote denial of service vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of IBM solidDB installed on the remote host is 6.5.x prior
to 6.5.0.12, 6.30.x prior to 6.30.0.55, 6.0.x prior to 6.0.0.1070, or
7.0.x prior to 7.0.0.4.  It therefore is reportedly affected by a
remote denial of service vulnerability that can be triggered by
calling a stored procedure with an omitted default value parameter."
  );
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IC94043");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IC94044");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IC88796");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IC88797");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21643599");
  # https://www-304.ibm.com/connections/blogs/PSIRT/entry/security_bulletin_ibm_soliddb_ibm_soliddb_universal_cache_stored_procedure_vulnerability_cve_2013_30311?lang=en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?64f69819");
  # https://www-304.ibm.com/connections/blogs/PSIRT/entry/ibm_security_bulletin_ibm_soliddb_ibm_soliddb_universal_cache
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?24195ffd");
  script_set_attribute(attribute:"solution", value:"Upgrade solidDB to version 6.0.0.1070 / 6.30.0.55 / 6.5.0.12 / 7.0.0.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/12/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:soliddb");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

  script_dependencies("soliddb_installed.nasl", "soliddb_detect.nasl");
  script_require_keys("SMB/solidDB/installed");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

get_kb_item_or_exit('SMB/solidDB/installed');

installs = get_kb_list_or_exit('SMB/solidDB/*/path');

if (report_paranoia < 2) get_kb_item_or_exit('Services/soliddb');

vuln = 0;
report = '';

foreach item (keys(installs))
{
  version = item - 'SMB/solidDB/';
  version = version - '/path';
  path = installs[item];

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  if (
    (ver[0] == 6 && ver[1] == 5  && ver[2] == 0 && ver[3] < 12) ||
    (ver[0] == 6 && ver[1] == 30 && ver[2] == 0 && ver[3] < 56) ||
    (ver[0] == 6 && ver[1] == 0  && ver[2] == 0 && ver[3] < 1070) ||
    (ver[0] == 7 && ver[1] == 0  && ver[2] == 0 && ver[3] < 4)
  )
  {
    vuln++;
    if (ver[0] == 6)
    {
      if(ver[1] == 0)
        fix = '6.0.0.1070';
      else if(ver[1] == 30)
        fix = '6.30.0.56';
      else fix = '6.5.0.12';
    }
    else
      fix = '7.0.0.4';

    report +=
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix + '\n';
  }
}

if (report)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    if (vuln > 1) s = 's of solidDB were found ';
    else s = ' of solidDB was found ';
    report =
      '\n  The following vulnerable install' + s + 'on the' +
      '\n  remote host :' +
      '\n' +
      report;
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
exit(0, 'No vulnerable installs of solidDB were detected on the remote host.');
