#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(60018);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2012/07/19 19:20:55 $");

  script_bugtraq_id(54068);
  script_osvdb_id(83153);

  script_name(english:"Western Digital ShareSpace WEB GUI Information Disclosure");
  script_summary(english:"Tries to retrieve admin/config.xml");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an application that is affected by an 
information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The web server for the Western Digital ShareSpace device identified
is affected by an information disclosure vulnerability due to an
improper configuration of access rights for the configuration file
'config.xml'.  An attacker can directly access the 'config.xml' file
without authentication and view sensitive information including
network settings, SMB users and hashed passwords, and administrator
credentials.");
  # https://www.sec-consult.com/files/20120618-0_WDShareSpaceWEBGUI_SensitiveDataDisclosure.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5d40bae6");
  script_set_attribute(attribute:"solution", value:
"No vendor-supplied patch is available at this time.  As a
recommendation, access to the administrative interface should be
allowed only from trusted networks.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");

  script_dependencies("wd_sharespace_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/sharespace");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, embedded:TRUE);

install = get_install_from_kb(appname:"sharespace", port:port, exit_on_fail:TRUE);
dir = install["dir"];

app = "Western Digital ShareSpace";
url = dir + "/admin/config.xml";

res = http_send_recv3(
  port         : port, 
  method       : "GET", 
  item         : url,
  exit_on_fail : TRUE
);
  
if (
  '<wixnas>' >!< res[2] ||
  '<nasshare>' >!< res[2] ||
  '<shareservice>' >!< res[2]
) audit(AUDIT_WEB_APP_NOT_AFFECTED, app, build_url(port:port, qs:'/'));

report = NULL;    
if (report_verbosity > 0)
{
  report = 
    '\nNessus was able exploit this issue using the following URL :\n' +
    '\n' + build_url(port:port, qs:url) +
    '\n';

  if (report_verbosity > 1)
  {
    count = 0;
    foreach line (split(res[2]))
    {
      info += line;
      count++;
      if (count >= 20) break;
    }

    snip =  crap(data:"-", length:30) + " snip " + crap(data:"-", length:30);
    report += 
      '\nHere are the contents of the file (limited to 20 lines) :\n' +
      '\n' + snip +
      '\n' + info + snip + 
      '\n';
  }
}
security_warning(port:port,extra:report);

