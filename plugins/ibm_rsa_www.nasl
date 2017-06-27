#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(45356);
  script_version ("$Revision: 1.10 $");
 
  script_name(english:"IBM Remote Supervisor Adapter Detection (HTTP)");
  script_summary(english:"Detects IBM RSA web server");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a remote management service." );
  script_set_attribute(attribute:"description", value:
"The remote web server has been fingerprinted as one embedded in IBM
Remote Supervisor Adapter (RSA) cards." );
  script_set_attribute(attribute:"see_also", value:"https://en.wikipedia.org/wiki/IBM_Remote_Supervisor_Adapter");
  script_set_attribute(attribute:"solution", value: "n/a" );
  script_set_attribute(attribute:"risk_factor", value: "None" );
  script_set_attribute(attribute:"plugin_publication_date", value: "2010/03/26");
 script_cvs_date("$Date: 2017/05/16 19:35:39 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:ibm:remote_supervisor_adapter_ii_firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");
  script_family(english:"Service detection");

  script_dependencie("httpver.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}

#
include ("global_settings.inc");
include ("misc_func.inc");
include ("http.inc");

port = get_http_port(default: 80, embedded: 1, dont_break: 1);

h = http_get_cache(port: port, item: "/", exit_on_fail: 1);
idx = stridx(h, '\r\n\r\n');
if (idx >= 0) h = substr(h, 0, idx+1);

if (egrep(string: h, pattern: "^Server:", icase: 1))
  exit(0, "The web server on port "+port+" sends a 'Server:' response header, unlike with IBM RSA cards.");

if (! egrep(string: h, pattern: "^HTTP/1\.[01] 302 "))
  exit(0, "/ is not redirected on port "+port+".");

if (! egrep(string: h, pattern:"^Location:.*/private/welcome.ssi", icase: 1))
  exit(0, "/ is not redirected to welcome.ssi on port "+port+", unlike with IBM RSA cards.");

w = http_send_recv3(port: port, item: "/", method:"GET", exit_on_fail: 1,
  username: "", password: "", follow_redirect: 1 );

if (w[0] !~ "^HTTP/1\.[01] 401 ")
  exit(0, "/ is not redirected to a protected page on port "+port+", unlike with IBM RSA cards.");

if (egrep(string:w[1], pattern: '^WWW-Authenticate: *Basic +realm=" Local System"'))
{
  security_note(port: port);
  set_kb_item(name: "Services/www/"+ port+"/embedded", value: TRUE);
  set_kb_item(name: "www/IBM_RSA", value: TRUE);
  set_kb_item(name: "www/"+port+"/IBM_RSA", value: TRUE);
}
else
  exit(0, "The authentication realm on port "+port+" is not ' Local System', unlike with IBM RSA cards.");
