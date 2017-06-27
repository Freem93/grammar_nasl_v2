#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63453);
  script_version("$Revision: 1.16 $");
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

  script_name(english:"Adobe Acrobat < 11.0.1 / 10.1.5 / 9.5.3 Multiple Vulnerabilities (APSB13-02)");
  script_summary(english:"Checks version of Adobe Acrobat");

  script_set_attribute(attribute:"synopsis",value:
"The version of Adobe Acrobat on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description",value:
"The version of Adobe Acrobat installed on the remote host is earlier
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

  script_set_attribute(attribute:"solution", value:"Upgrade to Adobe Acrobat 11.0.1 / 10.1.5 / 9.5.3 or later.");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("adobe_acrobat_installed.nasl");
  script_require_keys("SMB/Acrobat/Version");
  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("SMB/Acrobat/Version");
version_ui = get_kb_item('SMB/Acrobat/Version_UI');

if (isnull(version_ui)) version_report = version;
else version_report = version_ui;

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

path = get_kb_item_or_exit('SMB/Acrobat/Path');

if ( 
  (ver[0] == 9 && ver[1] < 5) ||
  (ver[0] == 9 && ver[1] == 5 && ver[2] < 3) ||
  (ver[0] == 10 && ver[1] < 1) ||
  (ver[0] == 10 && ver[1] == 1 && ver[2] < 5) ||
  (ver[0] == 11 && ver[1] == 0 && ver[2] < 1)
)
{
  port = get_kb_item('SMB/transport');
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : '+path+
      '\n  Installed version : '+version_report+
      '\n  Fixed version     : 11.0.1 / 10.1.5 / 9.5.3\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "Adobe Acrobat", version_report, path);
