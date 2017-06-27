#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10436);
 script_version ("$Revision: 1.19 $");
 script_cve_id("CVE-2000-0472");
 script_bugtraq_id(1316);
 script_osvdb_id(338);

 script_name(english:"INN < 2.2.3 verifycancels Option Cancel Request Message Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a remote buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote version of INN is between 2.0 and 2.2.2

There is a known security flaw in this version of INN which
may allow an attacker to execute arbitrary code on this server
is the option 'verifycancels' is enabled in inn.conf" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2000/Jun/86" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to version 2.2.3 or make sure that the option 
verifycancel is disabled on this server." );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2000/06/07");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/06/06");
 script_cvs_date("$Date: 2016/10/27 15:03:53 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Checks INN version");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2000-2016 Tenable Network Security, Inc.");
 script_family(english:"Gain a shell remotely");
 script_dependencie("find_service1.nasl");
 script_require_ports("Services/nntp", 119);
 exit(0);
}

#
# The script code starts here
#

port = get_kb_item("Services/nntp");
if(!port) port = 119;

if(get_port_state(port))
{
 soc = open_sock_tcp(port);
  if(soc)
  {
   # check for INN 2.0.0 to 2.2.2
   
   r = recv_line(socket:soc, length:1024);
    if(ereg(string:r, pattern:"^20[01] .* INN 2\.(([0-1]\..*)|(2\.[0-2])) .*$"))
    {
      security_note(port);
    }
  }
}
