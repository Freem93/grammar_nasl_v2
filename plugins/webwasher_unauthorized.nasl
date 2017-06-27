#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(16277);
  script_version ("$Revision: 1.14 $");
  script_cve_id("CVE-2005-0316");
  script_bugtraq_id(12394);
  script_osvdb_id(13234);

  script_name(english:"WebWasher Classic Server Mode Arbitrary Proxy CONNECT Request");
  script_summary(english:"Checks for the presence of WebWasher Proxy");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote service is vulnerable to an access control breach.'
  );

  script_set_attribute(
    attribute:'description',
    value:"There is a flaw in the remote WebWasher Proxy.  The Proxy, when issued
a CONNECT command for 127.0.0.1 (or localhost/loopback), will comply with
the request and initiate a connection to the local machine.

This bypasses any sort of firewalling as well as gives access to local
applications which are only bound to the loopback."
  );

  script_set_attribute(
    attribute:'solution',
    value: "Upgrade to a version of WebWasher greater than 3.3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(
    attribute:'see_also',
    value:'http://seclists.org/bugtraq/2005/Jan/350'
  );

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/01/31");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/01/28");
 script_cvs_date("$Date: 2016/11/29 20:13:38 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
  script_family(english:"Web Servers");
  script_dependencie("find_service1.nasl", "httpver.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8080);
  exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:8080);

w = http_send_recv3(method:"GET", item:"/nessus345678.html", port:port);
if (isnull(w)) exit(0);
r = w[1];

if ( "<html><head><title>WebWasher - Error 400: Bad Request</title>" >< r )
{
 if (egrep(pattern:"<small><i>generated .* by .* \(WebWasher ([0-2]\..*|3\.[0-3])\)</i></small>", string:r))
 {
   security_hole(port);
   exit(0);
 }
}
