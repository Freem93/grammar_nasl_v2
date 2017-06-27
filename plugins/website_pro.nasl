#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(10303);
  script_bugtraq_id(932);
  script_osvdb_id(239);
  script_cve_id("CVE-2000-0066");
  script_version ("$Revision: 1.24 $");

  script_name(english:"WebSite Pro Malformed URL Path Disclosure");
  script_summary(english:"Attempts to find the location of the remote web root");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote service is vulnerable to information disclosure.'
  );

  script_set_attribute(
    attribute:'description',
    value:"It was possible to discover the physical location of a
virtual web directory of this host by issuing the command :

  GET /HTTP1.0/

This can reveal valuable information to an attacker, allowing
them to focus their attack.
"
  );

  script_set_attribute(
    attribute:'solution',
    value: "Upgrade to Website Pro version 2.5 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:W/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(
    attribute:'see_also',
    value:'http://seclists.org/bugtraq/2000/Jan/165'
  );

  script_set_attribute(
    attribute:'see_also',
    value:'http://seclists.org/bugtraq/2001/Mar/271'
  );

 script_set_attribute(attribute:"plugin_publication_date", value: "2000/01/13");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/01/12");
 script_cvs_date("$Date: 2016/11/29 20:13:37 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2000-2016 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");
  script_dependencie("http_version.nasl", "find_service2.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("Settings/ThoroughTests");
  exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if ( ! thorough_tests ) exit(0, "This script only runs in 'thorough mode'.");

port = get_http_port(default:80);

w = http_send_recv_buf(port: port, data: 'GET /HTTP1.0/\r\n\r\n');
if (isnull(w))
 exit(0, "The web server on port "+port+" did not answer (broken request).");

r = strcat(w[0], w[1], '\r\n', w[2]);
if ("htdocs\HTTP" >< r) security_warning(port);
