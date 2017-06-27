#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66000);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/17 16:53:09 $");

  script_cve_id("CVE-2013-0912");
  script_bugtraq_id(58388);
  script_osvdb_id(91220);
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2013-04-16-1");

  script_name(english:"Mac OS X : Apple Safari < 6.0.4 SVG File Handling Arbitrary Code Execution");
  script_summary(english:"Check the Safari SourceVersion");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host contains a web browser that is affected by a remote
code execution vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Apple Safari installed on the remote Mac OS X 10.7 or
10.8 host is earlier than 6.0.4. It is, therefore, affected by an
arbitrary code execution vulnerability in WebKit related to handling
SVG files that can be exploited by tricking a victim into visiting a
specially crafted web page."
  );
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5701");
  script_set_attribute(attribute:"solution", value:"Upgrade to Apple Safari 6.0.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/17");

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

fixed_version = "6.0.4";

if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "Safari", version, path);
