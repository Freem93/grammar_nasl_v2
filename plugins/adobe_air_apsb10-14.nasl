#
# (C) Tenable Network Security, Inc.
#

if (NASL_LEVEL < 3000) exit(0);


include("compat.inc");

if (description)
{
  script_id(46858);
  script_version("$Revision: 1.51 $");
  script_cvs_date("$Date: 2016/11/11 19:58:28 $");

  script_cve_id(
    "CVE-2008-4546",
    "CVE-2009-3793",
    "CVE-2010-1297",
    "CVE-2010-2160",
    "CVE-2010-2161",
    "CVE-2010-2162",
    "CVE-2010-2163",
    "CVE-2010-2164",
    "CVE-2010-2165",
    "CVE-2010-2166",
    "CVE-2010-2167",
    "CVE-2010-2169",
    "CVE-2010-2170",
    "CVE-2010-2171",
    "CVE-2010-2172",
    "CVE-2010-2173",
    "CVE-2010-2174",
    "CVE-2010-2175",
    "CVE-2010-2176",
    "CVE-2010-2177",
    "CVE-2010-2178",
    "CVE-2010-2179",
    "CVE-2010-2180",
    "CVE-2010-2181",
    "CVE-2010-2182",
    "CVE-2010-2183",
    "CVE-2010-2184",
    "CVE-2010-2185",
    "CVE-2010-2186",
    "CVE-2010-2187",
    # "CVE-2010-2188",     # nb: Adobe removed this from APSB10-14.
    "CVE-2010-2189"
  );
  script_bugtraq_id(
    31537,
    40586,
    40779,
    40780,
    40781,
    40782,
    40783,
    40784,
    40785,
    40786,
    40787,
    40788,
    40789,
    40790,
    40791,
    40792,
    40793,
    40794,
    40795,
    40796,
    40797,
    # 40798,     # nb: Adobe removed this from APSB10-14.
    40799,
    40800,
    40801,
    40802,
    40803,
    40805,
    40806,
    40807,
    40808,
    40809
  );
  script_osvdb_id(
    50073,
    65141,
    65532,
    65572,
    65573,
    65574,
    65575,
    65576,
    65577,
    65578,
    65579,
    65580,
    65581,
    65582,
    65583,
    65584,
    65585,
    65586,
    65587,
    65588,
    65589,
    65590,
    65591,
    65592,
    65593,
    65594,
    65595,
    65596,
    65597,
    65598,
    65600,
    66119
  );
  script_xref(name:"CERT", value:"486225");
  script_xref(name:"Secunia", value:"40026");

  script_name(english:"Adobe AIR < 2.0.2.12610 Multiple Vulnerabilities (ASPB10-14)");
  script_summary(english:"Checks version of Adobe AIR");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a version of Adobe AIR that is
affected by multiple vulnerabilities.");

  script_set_attribute(attribute:"description", value:
"The remote Windows host contains a version of Adobe AIR that is
earlier than 2.0.2.12610.  Such versions are affected by multiple
vulnerabilities, such as memory corruption, buffer overflows, and
memory exhaustion, that could be exploited to cause an application
crash or even allow execution of arbitrary code.");
  
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb10-14.html");
  script_set_attribute(attribute:"solution",value:"Upgrade to Adobe AIR 2.0.2.12610 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-11-164");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Flash Player "newfunction" Invalid Pointer Use');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/10/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:air");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

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
  ver[0] < 2 ||
  (
    ver[0] == 2 &&
    (
      ver[1] == 0 && ver[2] < 2 ||
      (ver[2] == 2 && ver[3] < 12610)
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
