#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84289);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/06/22 14:07:24 $");

  script_cve_id("CVE-2015-1848", "CVE-2015-3983");
  script_bugtraq_id(74623, 74682);
  script_osvdb_id(122124, 122140);

  script_name(english:"PCS Daemon (pcsd) Cookie Signing Multiple Vulnerabilities");
  script_summary(english:"Checks for 'secure' and 'HttpOnly' flags on session cookies.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by multiple vulnerabilities due to a
failure by the PCS daemon (pcsd) to properly set flags in the
'Set-Cookie' header :

  - A security bypass vulnerability exists due to a failure
    to set the 'secure' flag. A remote attacker can exploit
    this to spoof cookies and bypass authorization checks.
    (CVE-2015-1848)

  - An information disclosure vulnerability exists due to a
    failure to set the 'HttpOnly' flag. A remote attacker
    can exploit this to obtain sensitive information from
    a cookie. (CVE-2015-3983)");
  # https://github.com/feist/pcs/commit/898204596a779673c88097bbdbe2d7ed6ed0cc8b
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5d6dab4e");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PCS Daemon (pcsd) 9.140 or higher. Alternatively, apply the
patch per the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date",value:"2015/05/12");
  script_set_attribute(attribute:"patch_publication_date",value:"2015/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/19");

  script_set_attribute(attribute:"plugin_type",value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:clusterlabs:pacemaker");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:fedora:pacemaker_configuration_system");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("pcsd_detect.nbin");
  script_require_ports("Services/www", 2224);
  script_require_keys("installed_sw/PCSD");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "PCSD";

get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:2224);

install = get_single_install(
  app_name     : app,
  port         : port
);

url = '/login';

res = http_send_recv3(
  method : "GET",
  item   : url,
  port   : port,
  exit_on_fail : TRUE
);

header_lines = split(res[1], keep:FALSE);

vuln_set_cookie = NULL;
foreach line (header_lines)
{
  raw_line = line;
  line = tolower(line);
  if(line =~ "^set-cookie\s*:\s*rack.session=" &&
     (line !~ ";\s*secure\s*(;|$)" || line !~ ";\s*httponly\s*(;|$)"))
  {
    vuln_set_cookie = raw_line;
    break;
  }
}

if(!isnull(vuln_set_cookie))
{
  if(report_verbosity > 0)
  {
    report = '\nThe following "Set-Cookie" response header is insecure :\n' +
    '\n  ' + vuln_set_cookie + '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, build_url(port:port, qs:"/"));
