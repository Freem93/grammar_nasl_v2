#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(21158);
  script_version("$Revision: 1.19 $");

  script_cve_id("CVE-2006-1392");
  script_bugtraq_id(17221);
  script_osvdb_id(24521);

  script_name(english:"Pubcookie Login Server index.cgi XSS");
  script_summary(english:"Tries to inject arbitrary script into Pubcookie Login Server");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that is affected by
several non-persistent, cross-site scripting flaws." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Pubcookie, an open source package for
intra-institutional, single-sign-on, end-user web authentication. 

The version of the Login Server component of Pubcookie installed on
the remote host fails to sanitize user-supplied input to various
parameters of the 'index.cgi' script before using it to generate
dynamic HTML.  An attacker may be able to exploit these issues to
cause arbitrary HTML and script code to be executed by a user's
browser in the context of the affected website, which could be used
to steal authentication credentials or mis-represent the affected
application." );
 script_set_attribute(attribute:"see_also", value:"http://pubcookie.org/news/20060306-login-secadv.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Pubcookie version 3.2.1b / 3.3.0a or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2006/03/28");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/03/06");
 script_cvs_date("$Date: 2015/01/14 20:12:25 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:university_of_washington:pubcookie");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");

port = get_http_port(default:80);
if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);

# A simple alert.
xss = "<script>alert('" + SCRIPT_NAME + "');</script>";

# Loop through various directories.
if (thorough_tests) dirs = list_uniq("/pubcookie", cgi_dirs());
else dirs = make_list(cgi_dirs());

test_cgi_xss(port: port, dirs: dirs, cgi: "/login.php", 
 qs: 'user=">' + urlencode(str:xss), pass_str: xss, 
 ctrl_re: 'type="hidden" name="(pre_sess_tok|first_kiss|pinit|create_ts)"');
