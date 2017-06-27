#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(69932);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/17 16:53:09 $");

  script_cve_id(
    "CVE-2013-1034",
    "CVE-2013-1899",
    "CVE-2013-1900",
    "CVE-2013-1901",
    "CVE-2013-2020",
    "CVE-2013-2021"
  );
  script_bugtraq_id(58876, 58878, 58879, 59434, 60118, 62449);
  script_osvdb_id(91960, 91961, 91962, 92834, 92835, 97386);
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2013-09-17-1");

  script_name(english:"Mac OS X : OS X Server < 2.2.2 Multiple Vulnerabilities");
  script_summary(english:"Checks OS X Server version.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote host is missing a security update for OS X Server."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Mac OS X 10.8 host has a version of OS X Server installed
that is prior to 2.2.2. It is, therefore, affected by the following
vulnerabilities :

  - Two vulnerabilities exist in the included ClamAV
    software, the most serious of which could allow an
    attacker to execute arbitrary code remotely.
    (CVE-2013-2020 / CVE-2013-2021)

  - Three vulnerabilities exist in the included PostgreSQL
    software, the most serious of which could result in
    data corruption or privilege escalation.
    (CVE-2013-1899 / CVE-2013-1900 / CVE-2013-1901)

  - Multiple cross-site scripting issues exist in the
    included Wiki Server software (CVE-2013-1034)"
  );
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5892");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2013/Sep/msg00004.html");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/528681/30/0/threaded");
  script_set_attribute(attribute:"solution", value:"Upgrade to Mac OS X Server version 2.2.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/04/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/17");

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

if (!ereg(pattern:"Mac OS X 10\.8([^0-9]|$)", string:os)) audit(AUDIT_OS_NOT, "Mac OS X 10.8");


version = get_kb_item_or_exit("MacOSX/Server/Version");

fixed_version = "2.2.2";
if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
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
