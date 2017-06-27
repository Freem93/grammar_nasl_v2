#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(10639);
  script_version ("$Revision: 1.28 $");
  script_cve_id("CVE-2001-0305");
  script_bugtraq_id(2385);
  script_osvdb_id(528);

  script_name(english:"Thinking Arts ES.One store.cgi StartID Parameter Traversal Arbitrary File Access");
  script_summary(english:"Checks for the presence of /cgi-bin/store.cgi");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote CGI script is vulnerable to an authentication bypass.'
  );

  script_set_attribute(
    attribute:'description',
    value:'The \'store.cgi\' cgi is installed. This CGI has
a well known security flaw that lets an attacker read arbitrary
files with the privileges of the http daemon (usually root or nobody).'
  );

  script_set_attribute(
    attribute:'solution',
    value:'Remove the \'store.cgi\' cgi from the server.'
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(
    attribute:'see_also',
    value:'http://seclists.org/bugtraq/2001/Feb/162'
  );

 script_set_attribute(attribute:"plugin_publication_date", value: "2001/03/25");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/02/16");
 script_cvs_date("$Date: 2016/12/14 20:33:27 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2001-2016 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");
  script_dependencie("http_version.nasl", "web_traversal.nasl", "no404.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);

if (get_kb_item("www/"+port+"/generic_traversal"))
  exit(0, 'The web server on port '+port+' is vulnerable to web directory traversal.');

foreach dir (cgi_dirs())
{
  u = strcat(dir, "/store.cgi?StartID=../../../../../../../../../etc/passwd%00.html");
  w = http_send_recv3(method:"GET", item: u, port:port, exit_on_fail: 1);
  buf = strcat(w[0], w[1], '\r\n', w[2]);
  if(egrep(pattern:".*root:.*:0:[01]:.*", string:buf))
  {
   if (report_verbosity > 0)
   {
     txt = '\nThis URL returns the content of /etc/passwd :\n' +
     	 build_url(port: port, qs: u) + '\n';
     security_hole(port:port, extra: txt);
   }
   else
 	security_hole(port);
    security_hole(port);
    exit(0);
  }
}

exit(0, 'The web server on port '+port+' is not vulnerable.');
