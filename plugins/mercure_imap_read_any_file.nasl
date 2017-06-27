#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(10382);
 script_version ("$Revision: 1.18 $");
 script_cve_id("CVE-2000-0318");
 script_bugtraq_id(1144);
 script_osvdb_id(290);
 
 script_name(english:"MERCUR Mailserver Local Traversal Arbitrary File Access");
 script_summary(english:"mercure imap version check"); 
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote IMAP server has a directory traversal vulnerability."
 );
 script_set_attribute( attribute:"description",  value:
"According to its banner, the version of MERCUR Messaging running
on the remote host has a directory traversal vulnerability.  An
authenticated, remote attacker could exploit this to read or write
arbitrary files on the system." );
 # https://web.archive.org/web/20000819133832/http://archives.neohapsis.com/archives/ntbugtraq/2000-q2/0057.html
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.nessus.org/u?b2817eb6"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to the latest version of this software."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:ND");
 script_set_attribute(attribute:"plugin_publication_date", value: "2000/04/25");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/04/13");
 script_cvs_date("$Date: 2016/11/18 19:03:16 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Misc.");

 script_copyright(english:"This script is Copyright (C) 2000-2016 Tenable Network Security, Inc.");

 script_dependencie("find_service1.nasl", "imap_overflow.nasl");
 script_exclude_keys("imap/false_imap");
 script_require_ports("Services/imap", 143);
 exit(0);
}

#
# The script code starts here
#


port = get_kb_item("Services/imap");
if(!port)port = 143;
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc > 0)
 {
  buf = recv_line(socket:soc, length:1024);
  close(soc);
  if(!buf)exit(0);
  if(ereg(pattern:"^.*MERCUR IMAP4-Server.*v3\.20\..*$",
  	  string:buf))
	  	security_warning(port);	
	
 }
}
