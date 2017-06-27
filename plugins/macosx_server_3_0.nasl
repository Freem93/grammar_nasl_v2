#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(70590);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/04/21 16:17:30 $");

  script_cve_id(
    "CVE-2012-3547",
    "CVE-2013-0269",
    "CVE-2013-1854",
    "CVE-2013-1855",
    "CVE-2013-1856",
    "CVE-2013-1857",
    "CVE-2013-5143"
  );
  script_bugtraq_id(55483, 57899, 58549, 58552, 58554, 58555, 63285);
  script_osvdb_id(85325, 90074, 91451, 91452, 91453, 91454, 98875);
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2013-10-22-5");

  script_name(english:"Mac OS X : OS X Server < 3.0 Multiple Vulnerabilities");
  script_summary(english:"Checks OS X Server version.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote host is missing a security update for OS X Server."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Mac OS X host has a version of OS X Server installed that
is prior to 3.0. It is, therefore, affected by the following
vulnerabilities :

  - A denial of service vulnerability exists in the
    included JSON Ruby Gem, which can be abused to exhaust
    all available memory resources. (CVE-2013-0269)

  - Multiple cross-site scripting vulnerabilities exist in
    the included Ruby on Rails software. (CVE-2013-1854 /
    CVE-2013-1855 / CVE-2013-1856 / CVE-2013-1857)

  - A buffer overflow exists in the included FreeRADIUS
    software that can be triggered when parsing the 'not
    after' timestamp in a client certificate when using
    TLS-based EAP methods. (CVE-2012-3547)

  - A logic issue exists whereby the RADIUS service could
    choose an incorrect certificate from a list of
    configured certificates."
  );
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5999");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2013/Oct/msg00006.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Mac OS X Server version 3.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/09/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:mac_os_x_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_server_services.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "MacOSX/Server/Version");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

version = get_kb_item_or_exit("MacOSX/Server/Version");

fixed_version = "3.0";
if (
  ereg(pattern:"Mac OS X 10\.[0-6]([^0-9]|$)", string:os) ||
  ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1
)
{
  set_kb_item(name:"www/0/XSS", value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "OS X Server", version);
