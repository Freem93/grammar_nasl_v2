#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(26065);
  script_version("$Revision: 1.18 $");

  script_cve_id("CVE-2007-4932");
  script_bugtraq_id(25695);
  script_osvdb_id(40149);
  script_xref(name:"EDB-ID", value:"4419");

  script_name(english:"Shop-Script admin.php Admin Panel Security Bypass");
  script_summary(english:"Tries to retrieve configuration settings");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
an authentication bypass vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Shop-Script, a shopping cart software
application written in PHP. 

The version of Shop-Script installed on the remote host fails to halt
execution of the script 'admin.php' if an attacker is not
authenticated. The attacker could then effectively bypass the
authentication check and gain control of the application. 

Note that the application is also likely affected by another
vulnerability that allows for arbitrary code execution by means of
specially crafted changes to the application's Appearance
configuration settings, although Nessus has not checked for this. 

By leveraging these two issues, an unauthenticated, remote attacker
would probably be able to execute arbitrary code on the affected host
subject to the privileges of the web server user id." );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20);
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/09/19");
 script_cvs_date("$Date: 2016/05/19 18:02:18 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

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

# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/shopscript", "/shop", "/store", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to exploit the issue to retrieve the general configuration settings.
  w = http_send_recv3(method:"GET",
    item:string(dir, "/admin.php?dpt=conf&sub=general"), 
    port:port
  );
  if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
  res = strcat(w[0], w[1], '\r\n', w[2]);

  # There's a problem if...
  if (
    # we gain access to the main form and...
    '<form action="admin.php' >< res && '<input type=hidden name=save_general' >< res &&
    # there's a redirection to the access_admin.php script
    egrep(pattern:"^Location: +access_admin\.php", string:res)
  )
  {
    security_hole(port);
    exit(0);
  }
}
