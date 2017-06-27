#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(53410);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/07/03 13:25:44 $");

  script_cve_id("CVE-2011-1290", "CVE-2011-1344");
  script_bugtraq_id(46822, 46849);
  script_osvdb_id(71182, 72690);

  script_name(english:"Mac OS X : Apple Safari < 5.0.5");
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
earlier than 5.0.5.  As such, it is potentially affected by several
issues :

  - An integer overflow issue in the handling of nodesets
    could lead to a crash or arbitrary code execution.
    (CVE-2011-1290)

  - A use-after-free issue in the handling of text nodes
    could lead to a crash or arbitrary code execution.
    (CVE-2011-1344)"
  );
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT4596");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2011/Apr/msg00002.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Apple Safari 5.0.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/03/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/14");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:safari");
  script_set_attribute(attribute:"plugin_type", value:"local");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

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
if (!egrep(pattern:"Darwin.* (9\.[0-8]\.|10\.)", string:uname)) audit(AUDIT_OS_NOT, "Mac OS X 10.5 / 10.6");


get_kb_item_or_exit("MacOSX/Safari/Installed");
path = get_kb_item_or_exit("MacOSX/Safari/Path", exit_code:1);
version = get_kb_item_or_exit("MacOSX/Safari/Version", exit_code:1);

fixed_version = "5.0.5";

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
