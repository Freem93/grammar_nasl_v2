#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(66809);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2016/05/17 16:53:09 $");

  script_cve_id(
    "CVE-2011-1945",
    "CVE-2011-3207",
    "CVE-2011-3210",
    "CVE-2011-4108",
    "CVE-2011-4109",
    "CVE-2011-4576",
    "CVE-2011-4577",
    "CVE-2011-4619",
    "CVE-2012-0050",
    "CVE-2012-2110",
    "CVE-2012-2131",
    "CVE-2012-2333",
    "CVE-2012-4929",
    "CVE-2013-0155",
    "CVE-2013-0276",
    "CVE-2013-0277",
    "CVE-2013-0333",
    "CVE-2013-0975",
    "CVE-2013-0984",
    "CVE-2013-0986",
    "CVE-2013-0987",
    "CVE-2013-0988",
    "CVE-2013-0990",
    "CVE-2013-1024",
    "CVE-2013-1854",
    "CVE-2013-1855",
    "CVE-2013-1856",
    "CVE-2013-1857"
  );
  script_bugtraq_id(
    47888,
    49469,
    49471,
    51281,
    51563,
    53158,
    53212,
    53476,
    55704,
    57192,
    57575,
    57896,
    57898,
    58549,
    58552,
    58554,
    58555,
    60099,
    60100,
    60328,
    60365,
    60368,
    60369
  );
  script_osvdb_id(
    74632,
    75229,
    75230,
    78186,
    78187,
    78188,
    78189,
    78190,
    78320,
    81223,
    81810,
    82110,
    85927,
    89025,
    89594,
    90072,
    90073,
    91451,
    91452,
    91453,
    91454,
    93617,
    93618,
    93620,
    93920,
    93923,
    93925,
    93926
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2013-06-04-1");
  script_xref(name:"EDB-ID", value:"25974");

  script_name(english:"Mac OS X Multiple Vulnerabilities (Security Update 2013-002)");
  script_summary(english:"Check for the presence of Security Update 2013-002");

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
does not have Security Update 2013-002 applied.  This update contains
numerous security-related fixes for the following components :

  - CoreMedia Playback (10.7 only)
  - Directory Service (10.6 only)
  - OpenSSL
  - QuickDraw Manager
  - QuickTime
  - Ruby (10.6 only)
  - SMB (10.7 only)"
  );
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-111/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-119/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-150/");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5784");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2013/Jun/msg00000.html");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/526808/30/0/threaded");
  script_set_attribute(attribute:"solution", value:"Install Security Update 2013-002 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Ruby on Rails JSON Processor YAML Deserialization Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/05/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/05");

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
  egrep(pattern:"^com\.apple\.pkg\.update\.security(\.10\.[67]\..+)?\.(2013\.00[2-9]|201[4-9]\.[0-9]+)(\.(snowleopard[0-9.]*|lion))?\.bom", string:packages)
) exit(0, "The host has Security Update 2013-002 or later installed and is therefore not affected.");
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
