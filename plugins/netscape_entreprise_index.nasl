#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(10691);
  script_version ("$Revision: 1.26 $");
  script_cve_id("CVE-2001-0250");
  script_bugtraq_id(2285);
  script_osvdb_id(571);

  script_name(english:"Netscape Enterprise Web Publishing INDEX Command Arbitrary Directory Listing");
  script_summary(english:"INDEX / HTTP/1.1 Information Disclosure");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote service is vulnerable to an information disclosure flaw.'
  );

  script_set_attribute(
    attribute:'description',
    value:"The remote web server gives a file listing when it is issued the command :

    INDEX / HTTP/1.1

An attacker may use this flaw to discover the internal
structure of your website, or to discover supposedly hidden
files."
  );

  script_set_attribute(
    attribute:'solution',
    value: "Disable web publishing or INDEX requests."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(
    attribute:'see_also',
    value:'http://seclists.org/bugtraq/2001/Jan/378'
  );

 script_set_attribute(attribute:"plugin_publication_date", value: "2001/06/15");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/01/24");
 script_cvs_date("$Date: 2016/11/23 20:31:33 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:netscape:enterprise_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2001-2016 Tenable Network Security, Inc.");
  script_family(english:"Web Servers");
  script_dependencie("find_service1.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/iplanet");
  exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default: 80);

w = http_send_recv3(method:"INDEX", item:"/", port: port);
if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
r = strcat(w[0], w[1], '\r\n', w[2]);
if("Content-Type: text/plain" >< r)
  {
   if("null" >< r)
  {
   if(egrep(pattern:"directory|unknown", string:r))security_warning(port);
  }
 }
