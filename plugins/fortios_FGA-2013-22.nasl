#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73527);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/04/23 20:09:18 $");

  script_cve_id("CVE-2013-1414");
  script_bugtraq_id(60861);
  script_osvdb_id(94724);
  script_xref(name:"EDB-ID", value:"26528");

  script_name(english:"Fortinet FortiOS < 4.3.13 / 5.0.3 Multiple XSRF");
  script_summary(english:"Checks the version of FortiOS.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple cross-site request forgery
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running FortiOS prior to 4.3.13 / 5.0.3. It is,
therefore, affected by multiple cross-site request forgery
vulnerabilities in web UI pages because they are not protected by XSRF
tokens. An attacker could potentially exploit this vulnerability to
hijack an authenticated user's session.");
  script_set_attribute(attribute:"see_also", value:"http://www.fortiguard.com/advisory/FGA-2013-22");
  script_set_attribute(attribute:"solution", value:"Upgrade to Fortinet FortiOS 4.3.13 / 5.0.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/07/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortios");
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

app_name = "FortiOS";
model = get_kb_item_or_exit("Host/Fortigate/model");
version = get_kb_item_or_exit("Host/Fortigate/version");
build = get_kb_item_or_exit("Host/Fortigate/build");
vuln = FALSE;

# Make sure device is FortiGate or FortiWiFi.
if (!preg(string:model, pattern:"forti(gate|wifi)", icase:TRUE)) audit(AUDIT_OS_NOT, app_name);

# Only 4.x and 5.x are affected.
if (version =~ "^4\.")
{
  fix = "4.3.13";
  fix_build = 664;
}
else if (version =~ "^5\.")
{
  fix = "5.0.3";
  fix_build = 208;
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
