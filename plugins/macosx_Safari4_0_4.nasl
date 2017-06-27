#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(42477);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2016/11/28 21:06:38 $");

  script_cve_id(
    "CVE-2009-2414",
    "CVE-2009-2416",
    "CVE-2009-2816",
    "CVE-2009-2841",
    "CVE-2009-2842"
  );
  script_bugtraq_id(36994, 36996, 36997);
  script_osvdb_id(56985, 56990, 59940, 59941, 59942);

  script_name(english:"Mac OS X : Apple Safari < 4.0.4");
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
earlier than 4.0.4.  As such, it is potentially affected by several
issues :

  - Multiple use-after-free issues exist in libxml2, the
    most serious of which could lead to a program crash.
    (CVE-2009-2414, CVE-2009-2416)

  - An issue in the handling of navigations initiated via 
    the 'Open Image in New Tab', 'Open Image in New Window'
    or 'Open Link in New Tab' shortcut menu options could
    be exploited to load a local HTML file, leading to
    disclosure of sensitive information. (CVE-2009-2842)

  - An issue involving WebKit's inclusion of custom HTTP
    headers specified by a requesting page in preflight
    requests in support of Cross-Origin Resource Sharing
    can facilitate cross-site request forgery attacks. 
    (CVE-2009-2816)

  - WebKit fails to issue a resource load callback to 
    determine if a resource should be loaded when it
    encounters an HTML 5 Media Element pointing to an 
    external resource, which could lead to undesired
    requests to remote servers. (CVE-2009-2841)"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://support.apple.com/kb/HT3949"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://lists.apple.com/archives/security-announce/2009/Nov/msg00001.html"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.securityfocus.com/advisories/18277"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Apple Safari 4.0.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119, 352, 399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/11/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/12");

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
if (!egrep(pattern:"Darwin.* (8\.|9\.[0-8]\.|10\.)", string:uname)) audit(AUDIT_OS_NOT, "Mac OS X 10.4 / 10.5 / 10.6");


get_kb_item_or_exit("MacOSX/Safari/Installed");
path = get_kb_item_or_exit("MacOSX/Safari/Path", exit_code:1);
version = get_kb_item_or_exit("MacOSX/Safari/Version", exit_code:1);

fixed_version = "4.0.4";

if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  set_kb_item(name:'www/0/XSRF', value:TRUE);

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
