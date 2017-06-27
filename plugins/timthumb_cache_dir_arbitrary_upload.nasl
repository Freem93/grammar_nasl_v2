#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56735);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/01/30 15:10:04 $");

  script_cve_id("CVE-2011-4106");
  script_bugtraq_id(48963);
  script_osvdb_id(74325);

  script_name(english:"TimThumb Cache Directory 'src' Parameter Arbitrary PHP File Upload");
  script_summary(english:"Attempts to exploit TimThumb.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a web application that allows an attacker
to upload arbitrary PHP files.");
  script_set_attribute(attribute:"description", value:
"The version of TimThumb hosted on the remote web server allows an
unauthenticated, remote attacker to upload arbitrary PHP files as
specified by input to the 'src' parameter and retrieved from third-
party sites to its cache directory. It's likely that these files can
then be executed by requesting them by means of a specially crafted
URL, which would result in arbitrary code execution subject to the
privileges of the web server process.

Note that this could be by design or because of a vulnerability in the
way TimThumb validates the third-party host. Regardless, it represents
a security vulnerability as it could allow for arbitrary PHP code
execution.");
  script_set_attribute(attribute:"see_also", value:"http://www.binarymoon.co.uk/2011/08/timthumb-2/");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1c76d435");
  script_set_attribute(attribute:"solution", value:
"Upgrade to TimThumb version 2.0 or higher or refer to the advisories
for software packages using TimThumb for upgrade instructions.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Wordpress Verve Meta Boxes 1.2.8 File Upload");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/08/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:binarymoon:timthumb");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:timthumb:timthumb");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2017 Tenable Network Security, Inc.");

  script_dependencies("wordpress_detect.nasl", "wordpress_timthumb_detect.nbin");
  script_require_keys("www/PHP", "installed_sw/WordPress", "installed_sw/TimThumb");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

app = "WordPress";
plugin = "TimThumb";
get_install_count(app_name:plugin, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : plugin,
  port     : port
);

dir = install['path'];
install_url = build_url(port:port, qs:dir);

src_parameter = "http://blogger.com." + SCRIPT_NAME;

get_url = dir + "?src=" + src_parameter;
res = http_send_recv3(item:get_url, port:port, method:"GET", exit_on_fail:TRUE);
if (
  ">TimThumb" >< res[2] &&
  ">Query String : src="+src_parameter+"<" >< res[2] &&
  (
    "error reading file " >< res[2] ||
    "remote file not a valid image" >< res[2] ||
    "remote file for " >< res[2] ||
    "can not be accessed. It is likely that the file permissions are restricted" >< res[2] ||
    "error writing temporary file" >< res[2] ||
    "local file for " >< res[2]
  )
)
{
  if (report_verbosity > 0)
  {
    header = 'Nessus was able to verify the issue with the following request';
    trailer = 'Note that Nessus has determined using the URL above only that\n' +
      'TimThumb allows files to be retrieved from arbitrary third-party\n' +
      'sites. It has not tried to actually exploit the issue to execute\n' +
      'arbitrary code.';

    report = get_vuln_report(
      header  : header,
      trailer : trailer,
      items   : get_url,
      port    : port
    );
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else
  audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, plugin + " script");
