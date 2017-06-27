#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
 script_id(11917);
 script_version("$Revision: 1.23 $");
 script_cvs_date("$Date: 2014/09/22 17:06:55 $");

 script_cve_id("CVE-2003-1042", "CVE-2003-1043", "CVE-2003-1044", "CVE-2003-1045", "CVE-2003-1046");
 script_bugtraq_id(8953);
 script_osvdb_id(2843,6387,6388,6389,6390);

 script_name(english:"Bugzilla < 2.16.4 / 2.17.5 Multiple Vulnerabilities (SQLi, ID)");
 script_summary(english:"Checks the Bugzilla version number");

 script_set_attribute(attribute:"synopsis", value:
"The web application on the remote host has multiple SQL injection
vulnerabilities.");
 script_set_attribute(attribute:"description", value:
"According to its version number, the remote Bugzilla bug tracker is
vulnerable to various flaws that could let a privileged user execute
arbitrary SQL commands on this host, which could allow an attacker to
obtain information about bugs marked as being confidential.");
 script_set_attribute(attribute:"see_also", value:"http://www.bugzilla.org/security/2.16.3/");
 script_set_attribute(attribute:"solution", value:"Upgrade to Bugzilla version 2.16.4 / 2.17.5 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2003/06/14");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/11/05");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:bugzilla");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");

 script_copyright(english:"This script is Copyright (C) 2003-2014 Tenable Network Security, Inc.");

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
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app = 'Bugzilla';
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80);

# Check the installed version.
install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

version = install['version'];
dir = install['path'];
install_loc = build_url(port:port, qs:dir+'/query.cgi');

if(ereg(pattern:"^(1\..*)|(2\.(16\.[0-3]|17\.[0-4]))[^0-9]*$",
       string:version))
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version : ' + version +
      '\n  URL     : ' + install_loc;
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_loc, version);
