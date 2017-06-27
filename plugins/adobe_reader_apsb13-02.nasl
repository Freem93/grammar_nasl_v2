#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63454);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/11/11 19:58:28 $");

  script_cve_id(
    "CVE-2012-1530",
    "CVE-2013-0601",
    "CVE-2013-0602",
    "CVE-2013-0603",
    "CVE-2013-0604",
    "CVE-2013-0605",
    "CVE-2013-0606",
    "CVE-2013-0607",
    "CVE-2013-0608",
    "CVE-2013-0609",
    "CVE-2013-0610",
    "CVE-2013-0611",
    "CVE-2013-0612",
    "CVE-2013-0613",
    "CVE-2013-0614",
    "CVE-2013-0615",
    "CVE-2013-0616",
    "CVE-2013-0617",
    "CVE-2013-0618",
    "CVE-2013-0619",
    "CVE-2013-0620",
    "CVE-2013-0621",
    "CVE-2013-0622",
    "CVE-2013-0623",
    "CVE-2013-0624",
    "CVE-2013-0626",
    "CVE-2013-0627",
    "CVE-2013-1376"
  );
  script_bugtraq_id(
    57263,
    57264,
    57265,
    57268,
    57269,
    57270,
    57272,
    57273,
    57274,
    57275,
    57276,
    57277,
    57282,
    57283,
    57284,
    57285,
    57286,
    57287,
    57289,
    57290,
    57291,
    57292,
    57293,
    57294,
    57295,
    57296,
    57297,
    65275
  );
  script_osvdb_id(
    88970,
    88971,
    88972,
    88973,
    88974,
    88975,
    88976,
    88977,
    88978,
    88979,
    88980,
    88981,
    88982,
    88983,
    88984,
    88985,
    88986,
    88987,
    88988,
    88989,
    88990,
    88991,
    88992,
    88993,
    88994,
    88995,
    88996,
    102685
  );

  script_name(english:"Adobe Reader < 11.0.1 / 10.1.5 / 9.5.3 Multiple Vulnerabilities (APSB13-02)");
  script_summary(english:"Checks version of Adobe Reader");

  script_set_attribute(attribute:"synopsis",value:
"The version of Adobe Reader on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description",value:
"The version of Adobe Reader installed on the remote host is earlier
than 11.0.1 / 10.1.5 / 9.5.3 and is, therefore, affected by multiple
vulnerabilities :

  - Multiple, unspecified memory corruption errors exist.
    (CVE-2012-1530, CVE-2013-0601, CVE-2013-0605,
    CVE-2013-0616, CVE-2013-0619, CVE-2013-0620,
    CVE-2013-0623)

  - A use-after-free vulnerability exists. (CVE-2013-0602)

  - Multiple heap overflow vulnerabilities exist. 
    (CVE-2013-0603, CVE-2013-0604)

  - Multiple stack overflow vulnerabilities exist.
    (CVE-2013-0610, CVE-2013-0626)

  - Multiple buffer overflow vulnerabilities exist.
    (CVE-2013-0606, CVE-2013-0612, CVE-2013-0615,
    CVE-2013-0617, CVE-2013-0621, CVE-2013-1376)

  - Multiple integer overflow vulnerabilities exist.
    (CVE-2013-0609, CVE-2013-0613)

  - A local privilege escalation vulnerability exists.
    (CVE-2013-0627)

  - Multiple logic error vulnerabilities exist. 
    (CVE-2013-0607, CVE-2013-0608, CVE-2013-0611,
    CVE-2013-0614, CVE-2013-0618)

  - Multiple security bypass vulnerabilities exist.
    (CVE-2013-0622, CVE-2013-0624)");

  script_set_attribute(attribute:"solution", value:"Upgrade to Adobe Reader 11.0.1 / 10.1.5 / 9.5.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb13-02.html");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat_reader");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:'Windows');
  script_copyright(english:'This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.');

  script_dependencies('adobe_reader_installed.nasl');
  script_require_keys('SMB/Acroread/Version');
  exit(0);
}


include('audit.inc');
include('global_settings.inc');

info =  '';
info2 = '';
vuln = 0;
vers = get_kb_list('SMB/Acroread/Version');
if (isnull(vers)) audit(AUDIT_KB_MISSING, 'SMB/Acroread/Version');

foreach version (vers)
{
  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  path = get_kb_item('SMB/Acroread/'+version+'/Path');
  if (isnull(path)) path = 'n/a';

  verui = get_kb_item('SMB/Acroread/'+version+'/Version_UI');
  if (isnull(verui)) verui = version;

  if ( 
    (ver[0] == 9 && ver[1]  < 5) ||
    (ver[0] == 9 && ver[1] == 5 && ver[2] < 3) ||
    (ver[0] == 10 && ver[1] < 1) ||
    (ver[0] == 10 && ver[1] == 1 && ver[2] < 5) ||
    (ver[0] == 11 && ver[1] == 0 && ver[2] < 1)
  )
  {
    vuln++;
    info += '\n  Path              : '+path+
            '\n  Installed version : '+verui+
            '\n  Fixed version     : 11.0.1 / 10.1.5 / 9.5.3\n';
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
