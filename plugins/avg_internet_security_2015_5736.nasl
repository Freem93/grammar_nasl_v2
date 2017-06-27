#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88933);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/04/29 19:06:03 $");

  script_cve_id("CVE-2015-8578");
  script_bugtraq_id(78813);
  script_osvdb_id(131496);

  script_name(english:"AVG Internet Security 2015.5736 Address Space Layout Disclosure");
  script_summary(english:"Checks the AVG Internet Security version.");

  script_set_attribute(attribute:"synopsis", value:
"An antivirus application installed on the remote Windows host is
affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The AVG Internet Security application installed on the remote Windows
host is a version between 2015.5315 through 2015.5751, inclusive, with
a virus definition database prior to version 9364. It is, therefore,
affected by an information disclosure vulnerability due to insecure
allocation of memory pages with Read, Write, and Execute (RWX)
permissions at constant predictable addresses when protecting
user-mode processes. An unauthenticated, remote attacker can exploit
this to bypass the DEP and ASLR protection mechanisms, resulting in
the disclosure of the address space layout.");
  script_set_attribute(attribute:"see_also", value:"http://www.avg.com/us-en/avg-release-notes");
  # http://breakingmalware.com/vulnerabilities/sedating-watchdog-abusing-security-products-bypass-mitigations/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4927ba47");
  # http://www.darkreading.com/endpoint/known-security-flaw-found-in-more-antivirus-products/d/d-id/1323480
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f75f1b1b");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version of AVG Internet Security.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:avg:internet_security");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("avg_internet_security_installed.nbin");
  script_require_keys("installed_sw/AVG Internet Security");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app = "AVG Internet Security";
install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);
path    = install["path"];
version = install["version"];
dbVerCore = install["vdbCore"];
dbVerAvi = install["vdbAvi"];
vuln = FALSE;
port = NULL;

# Check Version
if(dbVerCore == UNKNOWN_VER || dbVerAvi == UNKNOWN_VER) audit(AUDIT_UNKNOWN_APP_VER, app);
if (ver_compare(ver:version, fix:"2015.5315", strict:FALSE) >= 0 && ver_compare(ver:version, fix:"2015.5751", strict:FALSE) <= 0 )
{
  if (dbVerAvi < 9364)
    vuln = TRUE;
  else
    audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);

# Prepare Report
if (vuln)
{
  port = get_kb_item('SMB/transport');
  if (!port) port = 445;
  report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  DB core version   : ' + dbVerCore +
      '\n  DB AVI version    : ' + dbVerAvi +
      '\n  Fix               : Update to version 2015.5856 or DB AVI version 9364'+
      '\n';
  security_report_v4(severity: SECURITY_WARNING, port:port, extra:report);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);

