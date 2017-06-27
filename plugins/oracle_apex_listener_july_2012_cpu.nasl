#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78077);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/10/07 13:58:54 $");

  script_cve_id("CVE-2012-1740");
  script_bugtraq_id(54498);
  script_osvdb_id(83950);

  script_name(english:"Oracle Application Express Listener Remote Information Disclosure Vulnerability (July 2012 CPU)");
  script_summary(english:"Checks the version of Oracle Application Express install.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Application Express installation is affected by an
unspecified information disclosure vulnerability.");
  # http://www.oracle.com/technetwork/topics/security/cpujul2012-392727.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bd39edea");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2012 Oracle Critical
Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/07");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:application_express_listener");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("oracle_apex_listener_detect.nbin");
  script_require_keys("installed_sw/Oracle Application Express Listener");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app_name = "Oracle Application Express Listener";

get_kb_item_or_exit("installed_sw/" + app_name);

install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE, combined:TRUE);

version = install["version"];
port = install["port"];
path = install["path"];

if (isnull(port)) port = 0;

fix = "1.1.4";
if (version =~ "^1\.1\." && ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  report = '';
  if (port != 0)
    report += '\n  URL               : ' + build_url(port:port, qs:path);
  else
    report += '\n  Path              : ' + path;

  if (report_verbosity > 0)
  {
    report += '\n  Installed version : ' + version +
              '\n  Fixed version     : ' + fix +
              '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else
{
  if (port == 0) audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);
  else audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, build_url(port:port, qs:path), version);
}
