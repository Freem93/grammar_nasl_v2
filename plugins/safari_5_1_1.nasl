#
# (C) Tenable Network Security, Inc.
#


if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");


if (description)
{
  script_id(56483);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/19 18:02:18 $");

  script_cve_id(
    "CVE-2011-1440",
    "CVE-2011-2338",
    "CVE-2011-2339",
    "CVE-2011-2341",
    "CVE-2011-2351",
    "CVE-2011-2352",
    "CVE-2011-2354",
    "CVE-2011-2356",
    "CVE-2011-2359",
    "CVE-2011-2788",
    "CVE-2011-2790",
    "CVE-2011-2792",
    "CVE-2011-2797",
    "CVE-2011-2799",
    "CVE-2011-2800",
    "CVE-2011-2805",
    "CVE-2011-2809",
    "CVE-2011-2811",
    "CVE-2011-2813",
    "CVE-2011-2814",
    "CVE-2011-2815",
    "CVE-2011-2816",
    "CVE-2011-2817",
    "CVE-2011-2818",
    "CVE-2011-2819",
    "CVE-2011-2820",
    "CVE-2011-2823",
    "CVE-2011-2827",
    "CVE-2011-2831",
    "CVE-2011-3229",
    "CVE-2011-3232",
    "CVE-2011-3233",
    "CVE-2011-3234",
    "CVE-2011-3235",
    "CVE-2011-3236",
    "CVE-2011-3237",
    "CVE-2011-3238",
    "CVE-2011-3239",
    "CVE-2011-3241",
    "CVE-2011-3243"
  );
  script_bugtraq_id(
    47604,
    48479,
    48960,
    49279,
    49658,
    49850,
    50089,
    50163,
    51032
  );
  script_osvdb_id(
    72205,
    73511,
    74229,
    74238,
    74240,
    74242,
    74247,
    74250,
    74251,
    74255,
    74257,
    74258,
    74692,
    74698,
    75550,
    75844,
    76336,
    76337,
    76338,
    76339,
    76340,
    76341,
    76342,
    76343,
    76344,
    76345,
    76346,
    76347,
    76348,
    76349,
    76350,
    76351,
    76353,
    76382,
    76383,
    76384,
    76385,
    76386,
    76387,
    76388
  );

  script_name(english:"Safari < 5.1.1 Multiple Vulnerabilities");
  script_summary(english:"Checks Safari's version number");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host contains a web browser that is affected by several
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The version of Safari installed on the remote Windows host is earlier
than 5.1.1.  Thus, it is potentially affected by numerous issues in 
the following components :

  - Safari
  - WebKit"
  );
  # http://vttynotes.blogspot.com/2011/10/cve-2011-3229-steal-files-and-inject-js.html
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.nessus.org/u?95007eac"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://support.apple.com/kb/HT5000"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://lists.apple.com/archives/security-announce/2011/Oct/msg00004.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to Safari 5.1.1 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/04/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:safari");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("safari_installed.nasl");
  script_require_keys("SMB/Safari/FileVersion");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


version = get_kb_item_or_exit("SMB/Safari/FileVersion");

version_ui = get_kb_item("SMB/Safari/ProductVersion");
if (isnull(version_ui)) version_ui = version;

fixed_version = '5.34.51.22';
fixed_version_ui = '5.1.1 (7534.51.22)';

if (ver_compare(ver:version, fix:fixed_version) == -1)
{
  if (report_verbosity > 0)
  {
    path = get_kb_item("SMB/Safari/Path");
    if (isnull(path)) path = "n/a";

    report = 
      '\n  Path              : ' + path + 
      '\n  Installed version : ' + version_ui + 
      '\n  Fixed version     : ' + fixed_version_ui + '\n';
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
}
else exit(0, "The remote host is not affected since Safari " + version_ui + " is installed.");
