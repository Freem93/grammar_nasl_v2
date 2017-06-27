#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73523);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/04/23 20:09:18 $");

  script_cve_id("CVE-2013-6826");
  script_bugtraq_id(63663);
  script_osvdb_id(99780);

  script_name(english:"Fortinet FortiAnalyzer < 4.3.7 / 5.0.5 Multiple XSRF");
  script_summary(english:"Checks version of FortiAnalyzer");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple cross-site request forgery
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running FortiAnalyzer prior to 4.3.7 / 5.0.5. It
is, therefore, affected by multiple cross-site request forgery
vulnerabilities due to a failure to validate XSRF tokens in several
web UI scripts. An attacker could potentially exploit this
vulnerability to hijack an authenticated user's session.");
  script_set_attribute(attribute:"see_also", value:"http://www.fortiguard.com/advisory/FG-IR-13-018");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortinet FortiAnalyzer 4.3.7 / 5.0.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortianalyzer_firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/model", "Host/Fortigate/version", "Host/Fortigate/build");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "FortiAnalyzer";
model = get_kb_item_or_exit("Host/Fortigate/model");
version = get_kb_item_or_exit("Host/Fortigate/version");
build = get_kb_item_or_exit("Host/Fortigate/build");
vuln = FALSE;

# Make sure device is FortiAnalyzer.
if (!preg(string:model, pattern:"fortianalyzer", icase:TRUE)) audit(AUDIT_HOST_NOT, "a " + app_name + " device");

# Only 4.x and 5.x are affected.
if (version =~ "^4\.")
{
  fix = "4.3.7";
  fix_build = 705;
}
else if (version =~ "^5\.")
{
  fix = "5.0.5";
  fix_build = 266;
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version);

# If build number is available, this is the safest comparison.
# Otherwise compare version numbers.
if (build !~ "Unknown")
{
  if (int(build) < fix_build) vuln = TRUE;
}
else if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1) vuln = TRUE;

if (vuln)
{
  port = 0;
  set_kb_item(name:"www/"+port+"/XSRF", value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n  Model             : ' + model +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';

    security_warning(extra:report, port:port);
  }
  else security_warning(port:port);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version);
