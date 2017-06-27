#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(39768);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/11/28 21:06:38 $");

  script_cve_id("CVE-2009-1724", "CVE-2009-1725");
  script_bugtraq_id(35441, 35607);
  script_osvdb_id(55738, 55739);

  script_name(english:"Mac OS X : Apple Safari < 4.0.2");
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
earlier than 4.0.2 As such, it is potentially affected by two issues :

  - A vulnerability in WebKit's handling of parent and top
    objects may allow for cross-site scripting attacks.
    (CVE-2009-1724)

  - A memory corruption issue in WebKit's handling of
    numeric character references could lead to a crash or
    arbitrary code execution. (CVE-2009-1725)"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://support.apple.com/kb/HT3666"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://lists.apple.com/archives/security-announce/2009/Jul/msg00000.html"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.securityfocus.com/advisories/17297"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Apple Safari 4.0.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(79, 189);

  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:safari");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");
 
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
 
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
if (!egrep(pattern:"Darwin.* (8\.|9\.([0-6]\.|7\.[01][^0-9]))", string:uname)) audit(AUDIT_OS_NOT, "Mac OS X 10.4 / 10.5");


get_kb_item_or_exit("MacOSX/Safari/Installed");
path = get_kb_item_or_exit("MacOSX/Safari/Path", exit_code:1);
version = get_kb_item_or_exit("MacOSX/Safari/Version", exit_code:1);

fixed_version = "4.0.2";

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
