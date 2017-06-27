#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(20375);
  script_version("$Revision: 1.21 $");

  script_cve_id("CVE-2005-4606");
  script_bugtraq_id(16085);
  script_osvdb_id(22148);

  script_name(english:"Web Wiz check_user.asp txtUserName Parameter SQL Injection");
  script_summary(english:"Checks for txtUserName Parameter SQL injection vulnerability in Web Wiz products");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server has an ASP application that is affected by a SQL
injection vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running an ASP application from Web Wiz, such as
Password Login, Journal, Polls, or Site News. 

The installed version of the Web Wiz application fails to validate
user input to the 'txtUserName' parameter of the
'admin/check_user.asp' script before using it in database queries.  An
unauthenticated attacker may be able to leverage this issue to bypass
authentication, disclose sensitive information, modify data, or launch
attacks against the underlying database." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c6c7225d" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/Dec/338" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Web Wiz Password Login 1.72 / Journal 1.0.1 / Polls 3.07 /
Site News 3.07 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/01/03");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/12/30");
 script_cvs_date("$Date: 2016/11/02 20:50:26 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  script_require_keys("www/ASP");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 0);
if (!can_host_asp(port:port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/journal", "/news", "/poll", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Make sure the script exists.
  w = http_send_recv3(method:"GET", item:string(dir, "/admin/check_user.asp"), port:port);
  if (isnull(w)) exit(0);

  # If it does...
  if (egrep(pattern:"^Location: +unauthorised_user_page.htm", string:w[1])) {
    # Try to exploit the flaw to generate a syntax error.
    postdata = string(
      "txtUserName='", SCRIPT_NAME, "&",
      "txtUserPass=nessus&",
      "Submit=enter"
    );
    w = http_send_recv3(method:"POST", item: dir+"/admin/check_user.asp",
      port: port, content_type: "application/x-www-form-urlencoded",
      data: postdata);
    if (isnull(w)) exit(0);
    res = w[2];

    # There's a problem if we get a syntax error.
    if (
      string("query expression 'tblConfiguration.Username ='", SCRIPT_NAME) >< res &&
      egrep(pattern:"Microsoft OLE DB Provider for ODBC Drivers.+error '80040e14'", string:res)
    ) {
      security_hole(port);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      exit(0);
    }
  }
}
