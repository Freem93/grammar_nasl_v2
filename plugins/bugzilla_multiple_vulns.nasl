#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(13635);
 script_version("$Revision: 1.27 $");
 script_cvs_date("$Date: 2015/02/02 19:32:50 $");

 script_cve_id(
  "CVE-2004-0702",
  "CVE-2004-0703",
  "CVE-2004-0704",
  "CVE-2004-0705",
  "CVE-2004-0706",
  "CVE-2004-0707"
 );
 script_bugtraq_id(10698);
 script_osvdb_id(
  7780,
  7781,
  7782,
  7783,
  7784,
  7785,
  7786,
  7787,
  7788,
  7789,
  7790,
  7791
 );

 script_name(english:"Bugzilla < 2.16.6 / 2.18rc1 Multiple Vulnerabilities (XSS, SQLi, Priv Esc, more)");
 script_summary(english:"Checks Bugzilla version number");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI application that suffers from
multiple flaws.");
 script_set_attribute(attribute:"description", value:
"The remote Bugzilla bug tracking system, according to its version
number, is vulnerable to various flaws :

- An administrator may be able to execute arbitrary SQL
    commands on
    the remote host.

- There are instances of information leaks that may let an
    attacker
    know the database password (under certain circumstances,
    2.17.x only)
    or obtain the names of otherwise hidden products.

- A user with grant membership privileges may escalate his
    privileges
    and belong to another group.

- There is a cross-site scripting issue in the
    administrative web
    interface.

- Users passwords may be embedded in URLs (2.17.x only).

- Several information leaks exist that may allow users to
    determine the
    names of other users and non-users to obtain a list of
    products,
    including those that administrators might want to keep
    confidential.");
 script_set_attribute(attribute:"see_also", value:"http://www.bugzilla.org/security/");
 script_set_attribute(attribute:"solution", value:"Upgrade to 2.16.6 or 2.20 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/02/22");
 script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/13");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:bugzilla");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
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

if(ereg(pattern:"(1\..+|2\.(16\.[0-5]|1[789]\..+|2(0 *rc.*|1))[^0-9]*$)",
       string:version))
{
  set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

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
