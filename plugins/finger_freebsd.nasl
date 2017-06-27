#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(10534);
 script_version ("$Revision: 1.20 $");
 script_cve_id("CVE-2000-0915");
 script_bugtraq_id(1803);
 script_osvdb_id(433);

 script_name(english:"FreeBSD 4.1.1 Finger Arbitrary Remote File Access");
 script_summary(english:"Finger /path/to/file");
 
 script_set_attribute( attribute:"synopsis", value:
"The finger service running on the remote host has an arbitrary
file access vulnerability." );
 script_set_attribute( attribute:"description", value:
"The finger daemon running on the remote host will reveal the contents
of arbitrary files when given a command similar to the following :

  finger /etc/passwd@target

Which will return the contents of /etc/passwd." );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to the latest version of this finger daemon."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"plugin_publication_date", value: "2000/10/14");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/10/13");
 script_cvs_date("$Date: 2011/12/16 02:51:29 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Misc.");

 script_copyright(english:"This script is Copyright (C) 2000-2011 Tenable Network Security, Inc.");

 script_dependencies("find_service1.nasl", "finger.nasl");
 script_require_ports("Services/finger", 79);
 exit(0);
}

#
# The script code starts here
#

port = get_kb_item("Services/finger");
if(!port)port = 79;
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  buf = string("/etc/passwd\r\n");
  send(socket:soc, data:buf);
  data = recv(socket:soc, length:65535);
  close(soc);
  if(egrep(pattern:".*root:.*:0:[01]:", string:data))
  	security_hole(port);
 }
}
