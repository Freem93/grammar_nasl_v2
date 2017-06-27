#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79253);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/05/21 16:53:15 $");

  script_cve_id("CVE-2014-2334", "CVE-2014-2335", "CVE-2014-2336");
  script_bugtraq_id(70887, 70889, 70890);
  script_osvdb_id(114002, 114003, 114004);

  script_name(english:"Fortinet FortiAnalyzer / FortiManager < 5.0.7 Multiple Unspecified XSS (FG-IR-14-033)");
  script_summary(english:"Checks version of FortiAnalyzer and FortiManager");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple cross-site scripting
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of FortiAnalyzer or FortiManager
prior to 5.0.7. It is, therefore, affected by multiple unspecified
cross-site scripting vulnerabilities due to the web UI not properly
validating input before returning it to users. An attacker can exploit
these vulnerabilities to execute code in the security context of a
user's browser.");
  script_set_attribute(attribute:"see_also", value:"http://www.fortiguard.com/advisory/FG-IR-14-033");
  script_set_attribute(attribute:"see_also", value:"http://docs.fortinet.com/d/fortianalyzer-v5.0.7-release-notes");
  script_set_attribute(attribute:"see_also", value:"http://docs.fortinet.com/d/fortimanager-v5.0.7-release-notes");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortinet FortiAnalyzer / FortiManager version 5.0.7 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortianalyzer_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortimanager_firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

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

# Make sure device is FortiAnalyzer or FortiManager
match = eregmatch(string:model, pattern:"(fortimanager|fortianalyzer)", icase:TRUE);
if (!isnull(match[1]))
  app_name = match[1];
else
  audit(AUDIT_HOST_NOT, "a FortiAnalyzer or FortiManager device");

fix = "5.0.7";
fix_build = 321;

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

  set_kb_item(name:"www/"+port+"/XSS", value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  Model             : ' + model +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';

    security_warning(extra:report, port:port);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version);
