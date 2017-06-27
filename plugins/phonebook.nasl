#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(10564);
  script_version("$Revision: 1.39 $");
  script_cvs_date("$Date: 2014/05/26 15:30:09 $");

  script_cve_id("CVE-2000-1089");
  script_bugtraq_id(2048);
  script_osvdb_id(463);
  script_xref(name:"MSFT", value:"MS00-094");

  script_name(english:"Microsoft IIS Phone Book Service /pbserver/pbserver.dll Remote Overflow");
  script_summary(english:"Determines whether phonebook server is installed");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains software that is vulnerable to a buffer
overflow.");
  script_set_attribute(attribute:"description", value:
"The CGI /pbserver/pbserver.dll is subject to a buffer overflow attack
that may allow an attacker to execute arbitrary commands on this host.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms00-094");
  script_set_attribute(attribute:"solution", value:"Microsoft has released patches for Windows NT and 2000.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'MS00-094 Microsoft IIS Phone Book Service Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2000/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2000/12/06");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_DENIAL);
  script_copyright(english:"This script is Copyright (C) 2000-2014 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");

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


w = http_send_recv3(method:"GET",item:"/pbserver/pbserver.dll", port:port);
r = strcat(r[0], r[1], '\r\n', r[2]);
if("Bad Request" >< r)
  {
    r = http_send_recv3(method: "GET", port: port,
 item:string("/pbserver/pbserver.dll?OSArch=0&OSType=2&LCID=", crap(200), "&PBVer=0&PB=", crap(200)));
    r = http_send_recv3(method:"GET", item:"/pbserver/pbserver.dll", port:port);
    if (isnull(r)) security_hole(port);
  }

