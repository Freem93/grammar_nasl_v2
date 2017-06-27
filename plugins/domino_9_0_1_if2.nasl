#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(72802);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/05/09 00:31:20 $");

  script_cve_id("CVE-2014-0822");
  script_bugtraq_id(65427);
  script_osvdb_id(102912);

  script_name(english:"IBM Domino < 8.5.3 FP 6 IF 1 / 9.0.1 IF 2 DoS");
  script_summary(english:"Checks version of IBM Domino");

  script_set_attribute(attribute:"synopsis", value:"The remote server is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of IBM Domino (formerly IBM Lotus
Domino) on the remote host is 8.5.x prior to 8.5.3 FP 6 IF 1 or 9.0.x
prior to 9.0.1 IF 2. It is, therefore, affected by a denial of service
vulnerability. A remote, unauthenticated attacker could potentially
exploit this vulnerability to cause a crash of the Domino server.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21663023");
  script_set_attribute(attribute:"solution", value:"Upgrade to 8.5.3 FP 6 IF 1 / 9.0.1 IF 2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:lotus_domino_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("domino_installed.nasl");
  script_require_keys("Domino/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

# Check the version of Domino installed.
app_name = "IBM Domino";
ver = get_kb_item_or_exit("Domino/Version");
port = get_kb_item("Domino/Version_provided_by_port");
if (!port) port = 0;
version = NULL;
fix = NULL;
fix_ver = NULL;
fix_pack = NULL;
hotfix = NULL;

# Ensure sufficient granularity.
if (ver !~ "^(\d+\.){1,}\d+.*$") audit(AUDIT_VER_NOT_GRANULAR, app_name, port, ver);

# Only versions 8.5.x and 9.0.x are affected.
if (ver =~ "^8\.5($|(\.|\s).*$)")
{
  fix = "8.5.3 FP 6 IF 1";
  fix_ver = "8.5.3";
  fix_pack = 6;
  hotfix = 103;     # nb: 853FP6HF103_W64.exe is for 64-bit installs / 853FP6HF104_W32.exe for 32-bit
}
else if (ver =~ "^9\.0($|(\.|\s).*$)")
{
  fix = "9.0.1 IF 2";
  fix_ver = "9.0.1";
  fix_pack = 0;
  hotfix = 193;     # 901IF2INotes_901HF193_W64.zip for 64-bit installs / 901IF2INotes_901HF194_W32.zip for 32-bit
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
  ver_compare(ver:version[1], fix:fix_ver, strict:FALSE) == 0  && version[2] < fix_pack ||
  ver_compare(ver:version[1], fix:fix_ver, strict:FALSE) == 0  && version[2] == fix_pack && version[3] < hotfix
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n' +
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port:port);
}
else audit(AUDIT_LISTEN_NOT_VULN, app_name, port, ver);
