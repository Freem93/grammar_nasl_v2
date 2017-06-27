#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(15565);
 script_version("$Revision: 1.19 $");
 script_cvs_date("$Date: 2014/09/22 17:06:55 $");

 script_cve_id("CVE-2000-0421", "CVE-2001-0329");
 script_bugtraq_id(1199);
 script_osvdb_id(6362, 6363, 6364, 6365, 6392, 6393, 58527);

 script_name(english:"Bugzilla Multiple Remote Command Execution");
 script_summary(english:"Checks Bugzilla version number");

 script_set_attribute(attribute:"synopsis", value:"Arbitrary code may be run on the remote host.");
 script_set_attribute(attribute:"description", value:
"The remote Bugzilla bug tracking system, according to its version
number, is vulnerable to arbitrary command execution flaws due to a
lack of sanitization of user-supplied data in process_bug.cgi.");
 script_set_attribute(attribute:"solution", value:"Upgrade at version 2.12 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2000/05/11");
 script_set_attribute(attribute:"plugin_publication_date", value:"2004/10/25");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:bugzilla");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2004-2014 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencies("bugzilla_detect.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 script_require_keys("installed_sw/Bugzilla", "Settings/ParanoidReport");

 exit(0);
}

#
# The script code starts here
#

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("install_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app = 'Bugzilla';
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

version = install["version"];
dir = install["path"];
install_loc = build_url(port:port, qs:dir+'/query.cgi');

if(ereg(pattern:"^(2\.([0-9]|1[01]))[^0-9]*$", string:version))
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version : ' + version +
      '\n  URL     : ' + install_loc;
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_loc, version);
