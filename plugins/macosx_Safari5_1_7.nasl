#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59068);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/17 16:53:09 $");

  script_cve_id(
    "CVE-2011-3046",
    "CVE-2011-3056",
    "CVE-2012-0672",
    "CVE-2012-0676"
  );
  script_bugtraq_id(52369, 53404, 53407, 53446);
  script_osvdb_id(79893, 80294, 81787, 81792);

  script_name(english:"Mac OS X : Apple Safari < 5.1.7 Multiple Vulnerabilities");
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
earlier than 5.1.7.  It is, therefore, potentially affected by several
issues :

   - Two unspecified errors exist that can allow malicious
    sites to perform cross-site scripting attacks.
    (CVE-2011-3046, CVE-2011-3056)

  - An unspecified memory corruption error exists that can
    allow malicious sites to crash the application or
    potentially execute arbitrary code. (CVE-2012-0672)

  - A state-tracking issue exists that can allow malicious
    sites to populate HTML form values of other sites with
    arbitrary data. (CVE-2012-0676)"
  );
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5282");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2012/May/msg00002.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Apple Safari 5.1.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:safari");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

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

fixed_version = "5.1.7";

if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  set_kb_item(name:'www/0/XSS', value:TRUE);

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
