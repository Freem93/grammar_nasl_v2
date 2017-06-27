#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(10586);
  script_version ("$Revision: 1.27 $");
  script_cve_id("CVE-2001-0231");
  script_bugtraq_id(2172);
  script_osvdb_id(483);

  script_name(english:"News Desk newsdesk.cgi t Parameter Traversal Arbitrary File Access");
  script_summary(english:"Checks for the presence of /cgi-bin/newsdesk.cgi");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote service is vulnerable to information disclosure.'
  );

  script_set_attribute(
    attribute:'description',
    value:"The 'newsdesk.cgi' CGI is installed. This CGI has
a well known security flaw that lets an attacker read arbitrary
files with the privileges of the http daemon (usually root or nobody)."
  );

  script_set_attribute(
    attribute:'solution',
    value: "Remove newsdesk.cgi from the system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(
    attribute:'see_also',
    value:'http://seclists.org/bugtraq/2001/Jan/52'
  );

 script_set_attribute(attribute:"plugin_publication_date", value: "2001/01/04");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/01/03");
 script_cvs_date("$Date: 2016/11/23 20:31:33 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2001-2016 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");
  script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
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

foreach dir (cgi_dirs())
{
  w = http_send_recv3(method:"GET", port: port, item:string(dir, "/newsdesk.cgi?t=../../../../../../etc/passwd"));
  if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
  r = strcat(w[0], w[1], '\r\n', w[2]);
  if( egrep(pattern:".*root:.*:0:[01]:.*", string:r))
 	security_warning(port);
}
