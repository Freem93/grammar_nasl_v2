#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65579);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/02/04 22:38:29 $");

  script_cve_id(
    "CVE-2012-2824",
    "CVE-2012-2857",
    "CVE-2012-2889",
    "CVE-2013-0948",
    "CVE-2013-0949",
    "CVE-2013-0950",
    "CVE-2013-0951",
    "CVE-2013-0952",
    "CVE-2013-0953",
    "CVE-2013-0954",
    "CVE-2013-0955",
    "CVE-2013-0956",
    "CVE-2013-0958",
    "CVE-2013-0959",
    "CVE-2013-0960",
    "CVE-2013-0961",
    "CVE-2013-0962"
  );
  script_bugtraq_id(
    54203,
    54749,
    55676,
    57576,
    57580,
    57581,
    57582,
    57583,
    57584,
    57585,
    57586,
    57587,
    57588,
    57589,
    57590,
    58495,
    58496
  );
  script_osvdb_id(
    83246,
    84377,
    85775,
    89645,
    89646,
    89648,
    89649,
    89650,
    89651,
    89652,
    89653,
    89654,
    89655,
    89656,
    89657,
    91429,
    91430
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2013-03-14-2");

  script_name(english:"Mac OS X : Apple Safari < 6.0.3 Multiple Vulnerabilities");
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
"The version of Apple Safari installed on the remote Mac OS X 10.7 or
10.8 host is earlier than 6.0.3. It is, therefore, potentially
affected by several issues :

  - Multiple memory corruption vulnerabilities exist in
    WebKit that could lead to unexpected program termination
    or arbitrary code execution. (CVE-2012-2824 /
    CVE-2012-2857 / CVE-2013-0948 / CVE-2013-0949 /
    CVE-2013-0950 / CVE-2013-0951 / CVE-2013-0952 /
    CVE-2013-0953 / CVE-2013-0954 / CVE-2013-0955 /
    CVE-2013-0956 / CVE-2013-0958 / CVE-2013-0959 /
    CVE-2013-0960 / CVE-2013-0961)

  - A cross-site scripting issue exists in WebKit's handling
    of frame elements. (CVE-2012-2889)

  - A cross-site scripting issue exists in WebKit's handling
    of content pasted from a different origin.
    (CVE-2013-0962)"
  );
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5671");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2013/Mar/msg00003.html");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/526005/30/0/threaded");
  script_set_attribute(attribute:"solution", value:"Upgrade to Apple Safari 6.0.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:safari");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_Safari31.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "MacOSX/Safari/Installed");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

if (!ereg(pattern:"Mac OS X 10\.[78]([^0-9]|$)", string:os)) audit(AUDIT_OS_NOT, "Mac OS X 10.7 / 10.8");


get_kb_item_or_exit("MacOSX/Safari/Installed");
path = get_kb_item_or_exit("MacOSX/Safari/Path", exit_code:1);
version = get_kb_item_or_exit("MacOSX/Safari/Version", exit_code:1);

fixed_version = "6.0.3";

if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  set_kb_item(name:"www/0/XSS", value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + '\n';
    security_warning(port:0, extra:report);
  }
  else security_warning(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "Safari", version, path);
