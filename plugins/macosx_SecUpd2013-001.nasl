#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(65578);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/05/17 16:53:09 $");

  script_cve_id(
    "CVE-2011-3058",
    "CVE-2012-2088",
    "CVE-2012-3488",
    "CVE-2012-3489",
    "CVE-2012-3525",
    "CVE-2012-3756",
    "CVE-2013-0156",
    "CVE-2013-0333",
    "CVE-2013-0963",
    "CVE-2013-0966",
    "CVE-2013-0967",
    "CVE-2013-0971",
    "CVE-2013-0973"
  );
  script_bugtraq_id(
    52762,
    54270,
    55072,
    55074,
    55167,
    56552,
    57187,
    57575,
    57598,
    58509,
    58513,
    58514,
    58516
  );
  script_osvdb_id(
    80736,
    83628,
    84804,
    84805,
    84929,
    86871,
    87091,
    89026,
    89594,
    89660,
    91295,
    91296,
    91300,
    91301
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2013-03-14-1");

  script_name(english:"Mac OS X Multiple Vulnerabilities (Security Update 2013-001)");
  script_summary(english:"Check for the presence of Security Update 2013-001");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host is missing a Mac OS X update that fixes several
security issues."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running a version of Mac OS X 10.6 or 10.7 that
does not have Security Update 2013-001 applied.  This update contains
numerous security-related fixes for the following components :

  - Apache
  - CoreTypes (10.7 only)
  - International Components for Unicode
  - Identity Services (10.7 only)
  - ImageIO
  - Messages Server (Server only)
  - PDFKit
  - Podcast Producer Server (Server only)
  - PostgreSQL (Server only)
  - Profile Manager (10.7 Server only)
  - QuickTime
  - Ruby (10.6 Server only)
  - Security
  - Software Update
  - Wiki Server (10.7 Server only)

Note that the update also runs a malware removal tool that will remove
the most common variants of malware."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-055/");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5672");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2013/Mar/msg00002.html");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/526003/30/0/threaded");
  script_set_attribute(attribute:"solution", value:"Install Security Update 2013-001 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Ruby on Rails JSON Processor YAML Deserialization Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

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
if (!ereg(pattern:"Mac OS X 10\.[67]([^0-9]|$)", string:os)) audit(AUDIT_OS_NOT, "Mac OS X 10.6 / 10.7");
else if ("Mac OS X 10.6" >< os && !ereg(pattern:"Mac OS X 10\.6($|\.[0-8]([^0-9]|$))", string:os)) exit(0, "The remote host uses a version of Mac OS X Snow Leopard later than 10.6.8.");
else if ("Mac OS X 10.7" >< os && !ereg(pattern:"Mac OS X 10\.7($|\.[0-5]([^0-9]|$))", string:os)) exit(0, "The remote host uses a version of Mac OS X Lion later than 10.7.5.");

packages = get_kb_item_or_exit("Host/MacOSX/packages/boms", exit_code:1);
if (
  egrep(pattern:"^com\.apple\.pkg\.update\.security(\.10\.[67]\..+)?\.(2013\.00[1-9]|201[4-9]\.[0-9]+)(\.(snowleopard[0-9.]*|lion))?\.bom", string:packages)
) exit(0, "The host has Security Update 2013-001 or later installed and is therefore not affected.");
else
{
  if (report_verbosity > 0)
  {
    security_boms = egrep(pattern:"^com\.apple\.pkg\.update\.security", string:packages);

    report = '\n  Installed security updates : ';
    if (security_boms) report += str_replace(find:'\n', replace:'\n                               ', string:security_boms);
    else report += 'n/a';
    report += '\n';

    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
