#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86470);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/10/22 14:14:59 $");

  script_cve_id("CVE-2015-3620");
  script_bugtraq_id(74646);
  script_osvdb_id(121675);

  script_name(english:"Fortinet FortiAnalyzer FortiOS 5.0.x < 5.0.11 / 5.2.x < 5.2.2 Dataset Reports XSS");
  script_summary(english:"Checks the FortiOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Fortinet FortiAnalyzer FortiOS version running on the remote host
is 5.0.x prior to 5.0.11 or 5.2.x prior to 5.2.2. It is, therefore,
affected by a cross-site scripting vulnerability in the advanced
dataset reports page due to a failure to properly sanitize
user-supplied input to the 'sql-query' GET parameter before returning
it to users. An unauthenticated, remote attacker can exploit this, via
a crafted request, to execute arbitrary script code or HTML in the
user's browser session.");
  # http://www.fortiguard.com/advisory/2015-02-25-xss-vulnerability-in-web-action-quarantine-release-feature-of-fortimail
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?5728d4b4");
  script_set_attribute(attribute:"solution",value:
"Upgrade to Fortinet FortiOS version 5.0.11 / 5.2.2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date",value:"2015/02/25");
  script_set_attribute(attribute:"patch_publication_date",value:"2015/02/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/21");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/o:fortinet:fortianalyzer_firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

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

if (version =~ "^5\.0($|\.)")
{
  fix = "5.0.11";
  # http://docs.fortinet.com/uploaded/files/2281/fortios-v5.0.11-release-notes.pdf
  fix_build = 310;
}
else if(version =~ "^5\.2($|\.)")
{
  fix = "5.2.2";
  # http://docs.fortinet.com/uploaded/files/2374/fortianalyzer-v5.2.2-release-notes.pdf
  fix_build = 706;
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
  else security_warning(port:port);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version);
