#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(67130);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2014/10/17 20:35:31 $");

  script_cve_id("CVE-2013-1018", "CVE-2013-1019", "CVE-2013-1022");
  script_bugtraq_id(60098, 60102, 60104);
  script_osvdb_id(93616, 93622, 93624);
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2013-07-02-1");

  script_name(english:"Mac OS X Multiple Vulnerabilities (Security Update 2013-003)");
  script_summary(english:"Check for the presence of Security Update 2013-003");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host is missing a Mac OS X update that fixes several
security issues."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running a version of Mac OS X 10.6, 10.7, or 10.8
that does not have Security Update 2013-003 applied.  This update
contains several security-related fixes for the following component :

  - QuickTime

Successful exploitation of these issues could result in arbitrary code
execution."
  );
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5806");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2013/Jul/msg00000.html");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/527048/30/0/threaded");
  script_set_attribute(attribute:"solution", value:"Install Security Update 2013-003 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/05/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "Host/MacOSX/packages/boms");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");
if (!ereg(pattern:"Mac OS X 10\.[6-8]([^0-9]|$)", string:os)) audit(AUDIT_OS_NOT, "Mac OS X 10.6 / 10.7 / 10.8");
else if ("Mac OS X 10.6" >< os && !ereg(pattern:"Mac OS X 10\.6($|\.[0-8]([^0-9]|$))", string:os)) exit(0, "The remote host uses a version of Mac OS X Snow Leopard later than 10.6.8.");
else if ("Mac OS X 10.7" >< os && !ereg(pattern:"Mac OS X 10\.7($|\.[0-5]([^0-9]|$))", string:os)) exit(0, "The remote host uses a version of Mac OS X Lion later than 10.7.5.");
else if ("Mac OS X 10.8" >< os && !ereg(pattern:"Mac OS X 10\.8($|\.[0-4]([^0-9]|$))", string:os)) exit(0, "The remote host uses a version of Mac OS X Mountain Lion later than 10.8.4.");

packages = get_kb_item_or_exit("Host/MacOSX/packages/boms", exit_code:1);
if (
  egrep(pattern:"^com\.apple\.pkg\.update\.security(\.10\.[6-8]\..+)?\.(2013\.00[3-9]|201[4-9]\.[0-9]+)(\.(snowleopard[0-9.]*|lion))?\.bom", string:packages)
) exit(0, "The host has Security Update 2013-003 or later installed and is therefore not affected.");
else
{
  if (report_verbosity > 0)
  {
    security_boms = egrep(pattern:"^com\.apple\.pkg\.update\.security", string:packages);

    report = '\n  Installed security BOMs : ';
    if (security_boms) report += str_replace(find:'\n', replace:'\n                            ', string:security_boms);
    else report += 'n/a';
    report += '\n';

    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
