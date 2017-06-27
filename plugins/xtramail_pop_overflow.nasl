#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10325);
 script_version("$Revision: 1.45 $");
 script_cvs_date("$Date: 2016/11/01 19:59:57 $");

 script_cve_id("CVE-1999-1511");
 script_bugtraq_id(791);
 script_osvdb_id(253);

 script_name(english:"XtraMail POP3 PASS Command Remote Overflow");
 script_summary(english:"Attempts to overflow the in.pop3d buffers");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is running a mail server with a remote buffer overflow
vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote POP3 server is vulnerable to the following buffer overflow :

 USER test PASS <buffer>

This may allow an attacker to execute arbitrary commands as root on
the remote POP3 server.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/1999/Nov/128");
 script_set_attribute(attribute:"solution", value:"Contact the vendor for the latest update.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");

 script_set_attribute(attribute:"vuln_publication_date", value:"1999/11/10");
 script_set_attribute(attribute:"plugin_publication_date", value:"1999/11/10");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_MIXED_ATTACK);

 script_copyright(english:"This script is Copyright (C) 1999-2016 Tenable Network Security, Inc.");
 script_family(english:"Gain a shell remotely");

 script_dependencie("find_service1.nasl", "qpopper.nasl");
 script_exclude_keys("global_settings/supplied_logins_only");
 script_require_ports("Services/pop3", 110);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

port = get_service(svc:"pop3", default: 110, exit_on_fail: 1);
fake = get_kb_item("pop3/"+port+"/false_pop3");
if(fake)exit(0);

if(safe_checks())
{
 banner = get_kb_item(string("pop3/banner/", port));
 if(!banner){
 		soc = open_sock_tcp(port);
                if(!soc)exit(0);
		banner = recv_line(socket:soc, length:4096);
		if ( ! banner ) exit(0);
		close(soc);
		if (substr(banner,0,2) != '+OK') exit(0);	# Not a POP3 server!
	    }
 if(banner)
 {
  b = tolower(banner);
  if("xtramail" >< b)
  {
  if( ereg(pattern:".*1\.([0-9]|1[0-1])[^0-9].*",
   	string:b)
    )
    {
     data = "
reports this vulnerability using only information that was gathered.
Use caution when testing without safe checks enabled.";
     security_hole(port:port, extra:data);
    }
  }
 }
 exit(0);
}

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  r = recv_line(socket:soc, length:4096);
  if(!r)exit(0);

  c = string("USER test\r\n");
  send(socket:soc, data:c);
  d = recv_line(socket:soc, length:1024);
  c = string("PASS ", crap(2000), "\r\n");
  send(socket:soc, data:c);
  d = recv_line(socket:soc, length:1024, timeout:15);
  close(soc);

  soc = open_sock_tcp(port);
  if(soc)
  {
   r = recv_line(socket:soc, length:4096);
   if(!r)security_hole(port);
  }
  else
    security_hole(port);
 }
}

