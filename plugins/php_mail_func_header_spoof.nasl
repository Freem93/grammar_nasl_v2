# tony@libpcap.net
# http://libpcap.net
#
# See the Nessus Scripts License for details


include("compat.inc");

if(description)
{
  script_id(11444);

  script_cve_id("CVE-2002-0985", "CVE-2002-0986");
  script_bugtraq_id(5562);
  script_osvdb_id(2111, 2160);
  script_version ("$Revision: 1.17 $");

  script_name(english:"PHP Mail Function Header Spoofing");
 
 script_set_attribute(attribute:"synopsis", value:
"A remote web application can be used to forge data." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of PHP prior or equal to 4.2.2.

The mail() function does not properly sanitize user input.
This allows users to forge email to make it look like it is
coming from a different source other than the server.

Users can exploit this even if SAFE_MODE is enabled." );
 script_set_attribute(attribute:"solution", value:
"Contact your vendor for the latest PHP release." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/03/23");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/07/30");
 script_cvs_date("$Date: 2012/09/10 21:44:09 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:php:php");
script_end_attributes();

 
  summary["english"] = "Checks for version of PHP";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
 
  script_family(english:"CGI abuses");
  script_copyright(english:"(C) 2003-2012 tony@libpcap.net");
  if ( ! defined_func("bn_random") )
	script_dependencie("http_version.nasl");
  else
  	script_dependencie("http_version.nasl", "redhat-RHSA-2002-214.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

if ( get_kb_item("CVE-2002-0985" ) ) exit(0);

port = get_http_port(default:80);


if(get_port_state(port)) {
  banner = get_http_banner(port:port);
  if(!banner)exit(0);

  if(egrep(pattern:".*PHP/([0-3]\..*|4\.[0-1]\..*|4\.2\.[0-2][^0-9])", string:banner)) {
    security_warning(port);
  }
}
 
