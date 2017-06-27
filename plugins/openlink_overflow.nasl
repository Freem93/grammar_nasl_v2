#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10169);
 script_version("$Revision: 1.29 $");
 script_cvs_date("$Date: 2014/05/26 01:55:20 $");

 script_cve_id("CVE-1999-0943");
 script_osvdb_id(11269);

 script_name(english:"OpenLink Web Configurator GET Request Remote Overflow");
 script_summary(english:"OpenLink buffer overflow");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server has an application that is affected by a buffer
overflow vulnerability.");
 script_set_attribute(attribute:"description", value:
"It is possible to crash the remote web server by sending overly long
GET requests. An attacker may exploit this issue to crash the remote
web server or execute arbitrary code on the remote system.");
 script_set_attribute(attribute:"solution", value:"Unknown at this time.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

 script_set_attribute(attribute:"vuln_publication_date", value:"1999/10/15");
 script_set_attribute(attribute:"plugin_publication_date", value:"1999/10/19");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_copyright(english:"This script is Copyright (C) 1999-2014 Tenable Network Security, Inc.");
 script_family(english:"Gain a shell remotely");

 script_dependencie("http_version.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("Settings/ParanoidReport");
 script_require_ports(8000);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:8000);

foreach dir (cgi_dirs())
{
  url = string(dir, "/testcono");
  res = http_send_recv3(method:"GET", item:url, port:port);
  if(isnull(res)) exit(1, "Null response to " + url + " request.");

  url = string("/testcono?",crap(4096));
  res = http_send_recv3(method:"GET", item:url, port:port);
  if(isnull(res))
  {
    for(i = 0; i < 3 ; i++)
    {
      sleep(1);
      res = http_send_recv3(method:"GET", item:url, port:port);
      if(!isnull(res))
       exit(0);
    }
     security_hole(port);
  }
}
