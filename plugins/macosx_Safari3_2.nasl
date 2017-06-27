#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(34773);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/11/28 21:06:38 $");

  script_cve_id(
    # "CVE-2005-2096",
    # "CVE-2008-1767",
    "CVE-2008-2303",
    "CVE-2008-2317",
    # "CVE-2008-2327",
    # "CVE-2008-2332",
    # "CVE-2008-3608",
    # "CVE-2008-3623",
    # "CVE-2008-3642",
    "CVE-2008-3644",
    "CVE-2008-4216"
  );
  script_bugtraq_id(32291);
  script_osvdb_id(47289, 47290, 49940, 49941);

  script_name(english:"Mac OS X : Apple Safari < 3.2");
  script_summary(english:"Check the Safari SourceVersion");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by several
issues.");
  script_set_attribute(attribute:"description", value:
"The version of Apple Safari installed on the remote Mac OS X host is
earlier than 3.2.  As such, it is potentially affected by several
issues :

  - A signedness issue in Safari's handling of JavaScript 
    array indices could lead to a crash or arbitrary code 
    execution. (CVE-2008-2303)

  - A memory corruption issue in WebCore's handling of style
    sheet elements could lead to a crash or arbitrary code 
    execution. (CVE-2008-2317)

  - Disabling autocomplete on a form field may not prevent 
    the data in the field from being stored in the browser 
    page cache. (CVE-2008-3644)

  - WebKit's plug-in interface does not block plug-ins from 
    launching local URLs, which could allow a remote 
    attacker to launch local files in Safari and lead to the 
    disclosure of sensitive information. (CVE-2008-4216)");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT3298");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2008/Nov/msg00001.html");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/advisories/15730");
  script_set_attribute(attribute:"solution", value:"Upgrade to Apple Safari 3.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(189, 200, 399);

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/11/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:safari");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");
 
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
 
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
if (!egrep(pattern:"Darwin.* (8\.|9\.([0-4]\.|5\.0))", string:uname)) audit(AUDIT_OS_NOT, "Mac OS X 10.4 / 10.5");


get_kb_item_or_exit("MacOSX/Safari/Installed");
path = get_kb_item_or_exit("MacOSX/Safari/Path", exit_code:1);
version = get_kb_item_or_exit("MacOSX/Safari/Version", exit_code:1);

fixed_version = "3.2";

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
