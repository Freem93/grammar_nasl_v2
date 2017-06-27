#
# (C) Tenable Network Security, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include('compat.inc');

if (description)
{
  script_id(49173);
  script_version("$Revision: 1.25 $");
  script_cvs_date("$Date: 2017/04/27 14:49:39 $");

  script_name(english:"Adobe Reader < 9.4 / 8.2.5 Multiple Vulnerabilities (APSB10-21)");
  script_summary(english:"Checks version of Adobe Reader");

  script_cve_id(
    "CVE-2010-2883",
    "CVE-2010-2884",
    "CVE-2010-2888",
    "CVE-2010-2889",
    "CVE-2010-2890",
    "CVE-2010-3619",
    "CVE-2010-3620",
    "CVE-2010-3621",
    "CVE-2010-3622",
    "CVE-2010-3625",
    "CVE-2010-3626",
    "CVE-2010-3627",
    "CVE-2010-3628",
    "CVE-2010-3629",
    "CVE-2010-3630",
    "CVE-2010-3632",
    "CVE-2010-3656",
    "CVE-2010-3657",
    "CVE-2010-3658"
  );
  script_bugtraq_id(
    43057,
    43205,
    43722,
    43723,
    43724,
    43725,
    43726,
    43727,
    43729,
    43730,
    43732,
    43734,
    43735,
    43737,
    43738,
    43739,
    43741,
    43744,
    43746
  );
  script_osvdb_id(
    67849,
    68024,
    68413,
    68416,
    68418,
    68419,
    68420,
    68421,
    68422,
    68425,
    68426,
    68427,
    68428,
    68429,
    68430,
    68432,
    68433,
    68434,
    68435
  );
  script_xref(name:"CERT", value:"491991");
  script_xref(name:"Secunia", value:"41340");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Reader on the remote Windows host is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description",value:
"The version of Adobe Reader installed on the remote host is
earlier than 9.4 / 8.2.5.  Such versions are affected by multiple
code execution vulnerabilities.

Note that there have been reports that one or more of these issues
are being actively exploited in the wild.");
  # http://contagiodump.blogspot.com/2010/09/cve-david-leadbetters-one-point-lesson.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ac085b0c");
  # https://isc.sans.edu/diary/Adobe+AcrobatReader+0-day+in+Wild%2C+Adobe+Issues+Advisory/9523
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9783f73a");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/advisories/apsa10-02.html");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb10-21.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Reader 9.4 / 8.2.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-11-971");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe CoolType SING Table "uniqueName" Stack Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/09/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat_reader");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:'Windows');
  script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");

  script_dependencies('adobe_reader_installed.nasl');
  script_require_keys('SMB/Acroread/Version');
  exit(0);
}

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

  if ( ver[0]  < 8 ||
      (ver[0] == 8 && ver[1]  < 2) ||
      (ver[0] == 8 && ver[1] == 2  && ver[2] < 5) ||
      (ver[0] == 9 && ver[1]  < 4)
  )
  {
    vuln++;
    info += '\n  Path              : '+path+
            '\n  Installed version : '+verui+ 
            '\n  Fixed version     : 9.4 / 8.2.5\n';
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
