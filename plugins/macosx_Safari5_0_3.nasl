#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50653);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/05/17 16:53:09 $");

  script_cve_id(
    "CVE-2010-1812",
    "CVE-2010-1813",
    "CVE-2010-1814",
    "CVE-2010-1815",
    "CVE-2010-1822",
    "CVE-2010-3116",
    "CVE-2010-3257",
    "CVE-2010-3259",
    "CVE-2010-3803",
    "CVE-2010-3804",
    "CVE-2010-3805",
    "CVE-2010-3808",
    "CVE-2010-3809",
    "CVE-2010-3810",
    "CVE-2010-3811",
    "CVE-2010-3812",
    "CVE-2010-3813",
    "CVE-2010-3816",
    "CVE-2010-3817",
    "CVE-2010-3818",
    "CVE-2010-3819",
    "CVE-2010-3820",
    "CVE-2010-3821",
    "CVE-2010-3822",
    "CVE-2010-3823",
    "CVE-2010-3824",
    "CVE-2010-3826"
  );
  script_bugtraq_id(
    43079,
    43081,
    43083,
    44200,
    44206,
    44950,
    44952,
    44953,
    44954,
    44955,
    44956,
    44957,
    44958,
    44959,
    44960,
    44961,
    44962,
    44963,
    44964,
    44965,
    44967,
    44969,
    44970,
    44971
  );
  script_osvdb_id(
    66748,
    67460,
    67461,
    67862,
    67863,
    67930,
    67932,
    67933,
    68365,
    69426,
    69427,
    69430,
    69432,
    69433,
    69434,
    69435,
    69436,
    69437,
    69438,
    69439,
    69440,
    69442,
    69443,
    69444,
    89663
  );

  script_name(english:"Mac OS X : Apple Safari < 5.0.3 / 4.1.3");
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
earlier than 5.0.3 / 4.1.3.  As such, it is potentially affected by
numerous issues in its WebKit component that could allow arbitrary
code execution, session tracking, address bar spoofing, and other
sorts of attacks."
  );
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT4455");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2010/Nov/msg00002.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Apple Safari 5.0.3 / 4.1.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/09/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:safari");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_Safari31.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/uname", "Host/MacOSX/Version", "MacOSX/Safari/Installed");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");


if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

uname = get_kb_item_or_exit("Host/uname");
if (!egrep(pattern:"Darwin.* (8\.|9\.[0-8]\.|10\.)", string:uname)) audit(AUDIT_OS_NOT, "Mac OS X 10.4 / 10.5 / 10.6");


get_kb_item_or_exit("MacOSX/Safari/Installed");
path = get_kb_item_or_exit("MacOSX/Safari/Path", exit_code:1);
version = get_kb_item_or_exit("MacOSX/Safari/Version", exit_code:1);

if (egrep(pattern:"Darwin.* 8\.", string:uname)) fixed_version = "4.1.3";
else fixed_version = "5.0.3";

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
