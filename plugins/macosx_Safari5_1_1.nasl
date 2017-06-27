#
# (C) Tenable Network Security, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(56482);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2016/05/17 16:53:09 $");

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
    "CVE-2011-3230",
    "CVE-2011-3231",
    "CVE-2011-3232",
    "CVE-2011-3233",
    "CVE-2011-3234",
    "CVE-2011-3235",
    "CVE-2011-3236",
    "CVE-2011-3237",
    "CVE-2011-3238",
    "CVE-2011-3239",
    "CVE-2011-3241",
    "CVE-2011-3242",
    "CVE-2011-3243"
  );
  script_bugtraq_id(
    46614,
    47029,
    47604,
    48479,
    48840,
    48856,
    48960,
    49279,
    49658,
    49850,
    50089,
    50162,
    50163,
    50169,
    50180,
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
    76388,
    76389,
    76390,
    76391
  );
  script_xref(name:"EDB-ID", value:"17986");

  script_name(english:"Mac OS X : Apple Safari < 5.1.1");
  script_summary(english:"Check the Safari SourceVersion");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host contains a web browser that is affected by several
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The version of Apple Safari installed on the remote Mac OS X host is
earlier than 5.1.1. Thus, it is potentially affected by numerous
issues in the following components :

  - Safari
  - WebKit"
  );
  # http://vttynotes.blogspot.com/2011/10/cve-2011-3229-steal-files-and-inject-js.html
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.nessus.org/u?95007eac"
  );
  # http://vttynotes.blogspot.com/2011/10/cve-2011-3230-launch-any-file-path-from.html
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.nessus.org/u?de8e3a67"
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
    value:"Upgrade to Apple Safari 5.1.1 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apple Safari file:// Arbitrary Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/04/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:safari");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");
 
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
 
  script_dependencies("macosx_Safari31.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "MacOSX/Safari/Installed");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");


if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

if (!ereg(pattern:"Mac OS X 10\.[67]([^0-9]|$)", string:os)) audit(AUDIT_OS_NOT, "Mac OS X 10.6 / 10.7");


get_kb_item_or_exit("MacOSX/Safari/Installed");
path = get_kb_item_or_exit("MacOSX/Safari/Path", exit_code:1);
version = get_kb_item_or_exit("MacOSX/Safari/Version", exit_code:1);

fixed_version = "5.1.1";

if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Installed version : ' + version + 
      '\n  Fixed version     : ' + fixed_version + '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "Safari", version);
