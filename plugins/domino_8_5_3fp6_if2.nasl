#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73967);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/05/24 02:02:50 $");

  script_cve_id("CVE-2014-0892");
  script_bugtraq_id(67014);
  script_osvdb_id(106116);
  script_xref(name:"CERT", value:"350089");

  script_name(english:"IBM Domino 8.5.x < 8.5.3 Fix Pack 6 Interim Fix 2 NX Memory Protection Disabled");
  script_summary(english:"Checks version of IBM Domino");

  script_set_attribute(attribute:"synopsis", value:"The remote server is affected by a buffer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of IBM Domino (formerly IBM Lotus
Domino) on the remote host is 8.5.x prior to 8.5.3 Fix Pack 6 (FP6)
Interim Fix 2 (IF2). It is, therefore, more susceptible to
exploitation due to the GCC '-z execstack' flag being used during
compilation. This flag disables the memory protection provided by the
No eXecute (NX) bit allowing remote attackers to execute arbitrary
code more easily.

Note that this issue only affects Linux hosts running 32-bit versions
of Domino.");
  # Advisory
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21670264");
  # PSIRT blog post
  # https://www-304.ibm.com/connections/blogs/PSIRT/entry/bm_security_bulletin_ibm_notes_domino_fixes_for_multiple_vulnerabilities_cve_2014_0892_and_oracle_java_critical_patch_updates_for_oct_2013_jan_2014?lang=en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bd46d60e");
  script_set_attribute(attribute:"solution", value:"Upgrade to IBM Domino 8.5.3 FP6 IF2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/12");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:lotus_domino");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("domino_installed.nasl", "os_fingerprint.nasl");
  script_require_keys("Domino/Version", "Host/OS", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

# Only 32-bit Linux hosts are affected and a workaround is available
if (report_paranoia < 2) audit(AUDIT_PARANOID);

os = get_kb_item_or_exit("Host/OS");
if ("Linux" >!< os)
  audit(AUDIT_OS_NOT, "Linux");

app_name = "IBM Domino";
ver = get_kb_item_or_exit("Domino/Version");
port = get_kb_item("Domino/Version_provided_by_port");
if (!port) port = 0;
version = NULL;
fix = NULL;
fix_ver = NULL;
fix_pack = NULL;
hotfix = NULL;

# Ensure sufficient granularity
if (ver !~ "^(\d+\.){1,}\d+.*$") audit(AUDIT_VER_NOT_GRANULAR, app_name, port, ver);

# Only check for 8.0.x and 8.5.x versions
if (ver =~ "^8\.5($|[^0-9])")
{
  fix = "8.5.3 FP 6 IF 2";
  fix_ver = "8.5.3";
  fix_pack = 6;
  hotfix = 382;
}
else audit(AUDIT_LISTEN_NOT_VULN, app_name, port, ver);

# Breakdown the version into components.
version = eregmatch(string:ver, pattern:"^((?:\d+\.){1,}\d+)(?: FP(\d+))?(?: HF(\d+))?$");
if (isnull(version)) audit(AUDIT_UNKNOWN_APP_VER, app_name);

# Use 0 as a placeholder if no FP or HF. Version number itself was
# checked for in the granularity check.
if (!version[2]) version[2] = 0;
else version[2] = int(version[2]);
if (!version[3]) version[3] = 0;
else version[3] = int(version[3]);

# Compare current to fix and report as needed.
if (
  ver_compare(ver:version[1], fix:fix_ver, strict:FALSE) == -1 ||
  (ver_compare(ver:version[1], fix:fix_ver, strict:FALSE) == 0  && version[2] < fix_pack) ||
  (ver_compare(ver:version[1], fix:fix_ver, strict:FALSE) == 0  && version[2] == fix_pack && version[3] < hotfix)
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n' +
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port:port);
}
else audit(AUDIT_LISTEN_NOT_VULN, app_name, port, ver);
