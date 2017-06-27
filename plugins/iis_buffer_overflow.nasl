#
# (C) Tenable Network Security, Inc.
#
#  Modified by HD Moore <hdmoore@digitaldefense.net>
#        The original plugin actually took down the server,
#        this checks for the .htr ISAPI mapping but doesnt
#        actually try to overflow the server.

include("compat.inc");

if (description)
{
 script_id(10116);
 script_version("$Revision: 1.56 $");
 script_cvs_date("$Date: 2016/11/23 20:31:32 $");

 script_cve_id("CVE-1999-0874");
 script_bugtraq_id(307);
 script_osvdb_id(97);
  script_xref(name:"MSFT", value:"MS99-019");

 script_name(english:"Microsoft IIS ISM.DLL HTR Request Remote Overflow");
 script_summary(english:"IIS buffer overflow");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a remote buffer overflow
vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote IIS web server is affected by a remote buffer overflow
vulnerability. A malformed request for an .HTR, .STM, or .IDC file
could lead to a denial of service, or possibly remote arbitrary code
execution.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms99-019");
  script_set_attribute(attribute:"solution", value:"Apply the patch from the bulletin referenced above.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'MS02-018 Microsoft IIS 4.0 .HTR Path Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"1999/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"1999/06/22");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:iis");
  script_end_attributes();

  script_category(ACT_MIXED_ATTACK);
  script_copyright(english:"This script is Copyright (C) 1999-2016 Tenable Network Security, Inc. / Modifications by HD Moore <hdmoore@digitaldefense.net>");
  script_family(english:"Web Servers");

  script_dependencie("find_service1.nasl", "www_too_long_url.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");
  script_exclude_keys("www/too_long_url_crash");
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

banner = get_http_banner(port:port);
if ( "IIS" >!< banner ) exit(0);

if (http_is_dead(port:port)) exit(0);

if( safe_checks() )
{
  r = http_mk_get_req(item:"/nessus.htr", port:port);
  data = http_mk_buffer_from_req(req: r);
  soc  = http_open_socket(port);
  if(soc)
  {
   send(socket:soc, data:data);
   b = recv_line(socket:soc, length:1024);
   http_close_socket(soc);
   if (strlen(b) == 0) security_hole(port);
  }
  exit(0);
 }


r = http_mk_get_req(item:string(crap(4096), ".html"), port:port);
data1 = http_mk_buffer_from_req(req: r);
r = http_mk_get_req(item:string(crap(4096), ".htr"), port:port);
data2 = http_mk_buffer_from_req(req: r);

soc = http_open_socket(port);
if (! soc) exit(0);

send(socket:soc, data:data1);
b = recv_line(socket:soc, length:4096);
http_close_socket(soc);

if (strlen(b) == 0) exit(0);

soc = http_open_socket(port);
if (! soc) exit(0);
send(socket:soc, data:data2);
b = recv_line(socket:soc, length:4096);
http_close_socket(soc);
if (! strlen(b)) security_hole(port);
