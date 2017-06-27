#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83812);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/12/08 20:31:54 $");

  script_cve_id("CVE-2015-3611", "CVE-2015-3612");
  script_bugtraq_id(74444);
  script_osvdb_id(
    121003,
    121004,
    121005,
    121006,
    121007,
    144699,
    144700
  );

  script_name(english:"Fortinet FortiManager 5.0.x < 5.0.11 / 5.2.x < 5.2.2 Multiple Vulnerabilities (FG-IR-15-011)");
  script_summary(english:"Checks the version of FortiManager.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of FortiManager that is 5.0.x
prior to 5.0.11 or 5.2.x prior 5.2.2. It is, therefore, affected by
multiple vulnerabilities :

  - An unspecified flaw exists that allows an
    unauthenticated, remote attacker to inject arbitrary OS
    commands. (CVE-2015-3611)

  - A cross-site scripting (XSS) vulnerability exists due to
    improper validation of user-supplied input. An
    unauthenticated, remote attacker can exploit this, by
    convincing a user to follow a specially crafted link, to
    execute arbitrary script code in a user's browser
    session. (CVE-2015-3612)

  - An unspecified SQL injection vulnerability exists due to
    improper sanitization of user-supplied input before
    using it in SQL queries. (VulnDB 121003)

  - An unspecified local privilege escalation vulnerability
    exists in the command line interface. (VulnDB 121004)

  - A cross-site scripting vulnerability exists due to
    improper validation of user profile information.
    (VulnDB 121005)

  - An unspecified arbitrary file download vulnerability
    exists. An attacker can exploit this to disclose
    sensitive information. (VulnDB 121006)

  - An unspecified remote privilege escalation
    vulnerability exists. An attacker can exploit this by
    modifying specific parameters. (VulnDB 121007)");
  script_set_attribute(attribute:"see_also", value:"http://www.fortiguard.com/advisory/FG-IR-15-011");
  script_set_attribute(attribute:"see_also", value:"http://docs.fortinet.com/fortimanager/release-information");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortinet FortiManager version 5.0.11 / 5.2.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortimanager_firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/model", "Host/Fortigate/version", "Host/Fortigate/build");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

model   = get_kb_item_or_exit("Host/Fortigate/model");
version = get_kb_item_or_exit("Host/Fortigate/version");
build   = get_kb_item_or_exit("Host/Fortigate/build");

app_name = NULL;
vuln     = FALSE;

# Make sure device is FortiManager
match = eregmatch(string:model, pattern:"(fortimanager)", icase:TRUE);
if (!isnull(match[1]))
  app_name = match[1];
else
  audit(AUDIT_HOST_NOT, "a FortiManager device");

if (version =~ "^5\.2($|\.)")
{
  fix = "5.2.2";
  fix_build = "706";
}
else if (version =~ "^5\.0($|\.)")
{
  fix = "5.0.11";
  fix_build = "Unknown";
}
else
  audit(AUDIT_INST_VER_NOT_VULN, app_name, version);

# If build number is available, this is the safest comparison.
# Otherwise compare version numbers.
if (build !~ "Unknown" && fix_build !~ "Unknown")
{
  if (int(build) < int(fix_build)) vuln = TRUE;
}
else if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1) vuln = TRUE;

if (vuln)
{
  port = 0;

  set_kb_item(name:"www/"+port+"/XSS", value:TRUE);
  set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  Model             : ' + model +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';

    security_hole(extra:report, port:port);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version);
