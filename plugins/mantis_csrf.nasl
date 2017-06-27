#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(32324);
  script_version("$Revision: 1.19 $");
script_cvs_date("$Date: 2015/01/22 18:36:58 $");

  script_cve_id("CVE-2008-2276");
  script_osvdb_id(45214);
  script_xref(name:"EDB-ID", value:"5657");
  script_xref(name:"Secunia", value:"30270");

  script_name(english:"Mantis manage_user_create.php CSRF New User Creation");
  script_summary(english:"Sends a GET request for manage_user_create.php");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple cross-site request forgery vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The version of Mantis Bug Tracker installed on the remote host does
not verify the validity of HTTP requests before performing various
administrative actions.  If a remote attacker can trick a logged-in
administrator into viewing a specially crafted page, the vulnerability
could be leveraged to launch cross-site request forgery attacks 
against the affected application, such as creating additional users 
with administrator privileges. 

Note that the application is also reportedly affected by other issues,
including one that allows remote code execution provided an attacker
has administrator privileges, although Nessus did not explicitly test
for them." );
 script_set_attribute(attribute:"see_also", value:"http://www.mantisbt.org/bugs/view.php?id=8995" );
 script_set_attribute(attribute:"see_also", value:"http://www.attrition.org/pipermail/vim/2008-May/001980.html" );
  # http://mantisbt.svn.sourceforge.net/viewvc/mantisbt?revision=5132&view=revision
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c5db0035" );
 script_set_attribute(attribute:"see_also", value:"http://www.mantisbt.org/blog/?p=19" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Mantis 1.2.0a1 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(352);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/05/15");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:mantisbt:mantisbt");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");

  script_dependencies("mantis_detect.nasl");
  script_require_keys("installed_sw/MantisBT");
  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

port = get_http_port(default:80, php:TRUE);

app_name = "MantisBT";

install = get_single_install(app_name: app_name, port: port);
install_url = build_url(port:port, qs:install['path']);

# Test an install.
dir = install['path'];

# Send a GET request for manage_user_create.php.
w = http_send_recv3(
  method:"GET",
  item:dir + "/manage_user_create.php",
  port:port,
  exit_on_fail:TRUE
);

# There's a problem if we get redirected to the login form as the
# patch instead results in an application error unless a POST
# request was sent.
headers = w[1];
if (egrep(pattern:"^Location: +login_page\.php.+manage_user_create\.php", string:headers))
{
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  set_kb_item(name: 'www/'+port+'/XSRF', value: TRUE);
  security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, install_url);
