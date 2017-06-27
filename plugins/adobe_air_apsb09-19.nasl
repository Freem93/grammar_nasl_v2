#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(43069);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/11/11 19:58:28 $");

  script_cve_id(
    'CVE-2009-3794',
    'CVE-2009-3796',
    'CVE-2009-3797',
    'CVE-2009-3798',
    'CVE-2009-3799',
    'CVE-2009-3800'
  );
  script_bugtraq_id(37266, 37267, 37269, 37270, 37273, 37275);
  script_osvdb_id(60885, 60886, 60887, 60888, 60889, 60890);
  script_xref(name:"Secunia", value:"37584");

  script_name(english:"Adobe AIR < 1.5.3 Multiple Vulnerabilities (APSB09-19)");
  script_summary(english:"Checks version of Adobe AIR");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a version of Adobe AIR that is 
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host contains a version of Adobe AIR that is
earlier than 1.5.3.  Such versions are potentially affected by
multiple vulnerabilities :

  - A vulnerability in the parsing of JPEG data could lead
    to code execution. (CVE-2009-3794)

  - A data injection vulnerability could lead to code
    execution. (CVE-2009-3796)

  - A memory corruption vulnerability could lead to code
    execution. (CVE-2009-3797)

  - A memory corruption vulnerability could lead to code
    execution. (CVE-2009-3798)

  - An integer overflow vulnerability could lead to code
    execution. (CVE-2009-3799) 

  - Multiple crash vulnerabilities could lead to code
    execution. (CVE-2009-3800)");
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.adobe.com/support/security/bulletins/apsb09-19.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Adobe AIR 1.5.3 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(94, 119, 189, 399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/12/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:air");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("adobe_air_installed.nasl");
  script_require_keys("SMB/Adobe_AIR/Version");
  exit(0);
}

include("global_settings.inc");

version_ui = get_kb_item("SMB/Adobe_AIR/Version_UI");
version = get_kb_item("SMB/Adobe_AIR/Version");
if (isnull(version)) exit(1, "The 'SMB/Adobe_AIR/Version' KB item is missing.");

if (isnull(version_ui)) version_report = version;
else version_report = version_ui;

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  ver[0] < 1 ||
  (
    ver[0] == 1 &&
    (
      ver[1] < 5 ||
      (ver[1] == 5 && ver[2] < 3)
    )
  )
)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n' +
      'Adobe AIR ' + version_report + ' is currently installed on the remote host.\n';
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
  exit(0);
}
else exit(0, "The Adobe AIR "+version_report+" install is not affected.");
