#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99689);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2017/04/26 20:39:52 $");

  script_cve_id("CVE-2017-1274");
  script_bugtraq_id(98019);
  script_osvdb_id(155618);
  script_xref(name:"CERT", value:"574401");

  script_name(english:"IBM Domino IMAP EXAMINE Command Handling RCE (EMPHASISMINE)");
  script_summary(english:"Checks the version of IBM Domino.");

  script_set_attribute(attribute:"synopsis", value:
"A business collaboration application running on the remote host is
affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of IBM Domino (formerly IBM Lotus
Domino) running on the remote host is 8.5.1, 8.5.2, or 8.5.3 prior to
8.5.3 FP6 IF17, or else it is 9.0.0 or 9.0.1 prior to 9.0.1 FP8 IF2. It
is, therefore, affected by a remote code execution vulnerability due
to improper validation of user-supplied input when handling the IMAP
EXAMINE command. An authenticated, remote attacker can exploit this,
via a specially crafted mailbox name in an IMAP EXAMINE command, to
cause a stack-based buffer overflow, resulting in a denial of service
condition or the execution of arbitrary code.

EMPHASISMINE is one of multiple Equation Group vulnerabilities and
exploits disclosed on 2017/04/14 by a group known as the Shadow
Brokers.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg22002280");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM Domino version 8.5.3 FP6 IF17 / 9.0.1 FP8 IF2 or later.

Alternatively, customers using 8.5.1, 8.5.2, and 9.0.0 can open a
service request with IBM Support and reference SPR SKAIALJE9N for a
custom hotfix.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:domino");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:lotus_domino");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("domino_installed.nasl");
  script_require_keys("Domino/Version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

# Paranoid as special fixes are unknown to us
if (report_paranoia < 2) audit(AUDIT_PARANOID);

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

# Only check for 9.0.0.x / 9.0.1.x versions
if (ver =~ "^9\.0\.[01]($|[^0-9])")
{
  fix = "9.0.1 FP8 IF2";
  fix_ver = "9.0.1";
  fix_pack = 8;
  hotfix = 172;
}
else if (ver =~ "^8\.5\.[123]($|[^0-9])")
{
  fix = "8.5.3 FP6 IF17";
  fix_ver = "8.5.3";
  fix_pack = 6;
  hotfix = 3145;
}
else audit(AUDIT_LISTEN_NOT_VULN, app_name, port, ver);

# Breakdown the version into components.
version = pregmatch(string:ver, pattern:"^((?:\d+\.){1,}\d+)(?: FP(\d+))?(?: ?HF(\d+))?$");
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
  report =
    '\n' +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
}
else audit(AUDIT_LISTEN_NOT_VULN, app_name, port, ver);
