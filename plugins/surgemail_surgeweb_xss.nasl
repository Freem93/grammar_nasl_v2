#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(49709);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/13 15:33:30 $");

  script_cve_id("CVE-2010-3201");
  script_bugtraq_id(43679);
  script_osvdb_id(68323);

  script_name(english:"SurgeMail surgeweb XSS");
  script_summary(english:"XSS against surgeweb");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a cross-site scripting
vulnerability." );
  script_set_attribute(attribute:"description", value:
"The remote web server hosts a CGI script that fails to adequately
sanitize request strings with malicious JavaScript.  By leveraging
this issue, an attacker may be able to cause arbitrary HTML and script
code to be executed in a user's browser within the security context of
the affected site." );
  script_set_attribute(attribute:"see_also", value:"http://ictsec.se/?p=108");
  script_set_attribute(attribute:"see_also", value:"http://www.netwinsite.com/surgemail/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to SurgeMail 4.3g or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value: "2010/10/04");
  script_set_attribute(attribute:"plugin_publication_date", value: "2010/10/04");
  script_set_attribute(attribute:"patch_publication_date", value: "2010/05/26");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default: 80, embedded: 1);

if (! thorough_tests)
{
  b = get_http_banner(port: port, exit_on_fail: 1);
  if (! egrep(string: b, pattern: "^Server: *DManager"))
    exit(0, "The web server on port "+port+" does not look like surgeweb.");
}

if (thorough_tests)
  dirs = list_uniq(make_list("/", cgi_dirs()));
else
  dirs = make_list("/");

test_cgi_xss(port: port, cgi: "/surgeweb", dirs: dirs,
 pass_re: '"[^"]*">.*<script>alert.42.;</script>',
 ctrl_re: '> Welcome to SurgeWeb<', 
 qs: 'username_ex="><scri<script>alert(42);</script><input type="hidden');
