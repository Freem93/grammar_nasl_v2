#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(17973);
 script_version("$Revision: 1.10 $");
 script_cvs_date("$Date: 2016/11/19 01:42:51 $");

 script_cve_id("CVE-2005-0788");
 script_bugtraq_id(12802);
 script_osvdb_id(14671);

 script_name(english:"Lime Wire Multiple Remote Unauthorized Access");
 script_summary(english:"Checks for remote unauthorized access flaw in Lime Wire");

 script_set_attribute(attribute:"synopsis", value:
"Arbritrary files may be read on this host.");
 script_set_attribute(attribute:"description", value:
"The remote host seems to be running Lime Wire, a P2P file sharing program.

This version is vulnerable to remote unauthorized access flaws.
An attacker can access to potentially sensitive files on the 
remote vulnerable host.");
 script_set_attribute(attribute:"see_also", value:
"http://seclists.org/bugtraq/2005/Mar/239");
 script_set_attribute(attribute:"see_also", value:
"http://seclists.org/bugtraq/2005/Mar/325");
 script_set_attribute(attribute:"solution", value:
"Upgrade at least to version 4.8.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value:"2005/04/06");
 script_set_attribute(attribute:"vuln_publication_date", value:"2005/03/11");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
 script_family(english:"Misc.");

 script_dependencie("http_version.nasl", "os_fingerprint.nasl");
 script_require_ports(6346);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");

if(!port)port = 6346;
if(!get_port_state(port))exit(0);

banner = get_http_banner(port: port);
if(!banner)exit(0);

serv = strstr(banner, "Server");
if(egrep(pattern:"limewire", string:serv, icase:TRUE))
{
  req = http_get(item:"/gnutella/res/C:\Windows\win.ini", port:port);
  soc = http_open_socket(port);
  if(soc)
  {
   send(socket:soc, data:req);
   r = http_recv(socket:soc);
   http_close_socket(soc);
   if("[windows]" >< r)
   {
    security_warning(port);
    exit(0);
   }
  }
}
