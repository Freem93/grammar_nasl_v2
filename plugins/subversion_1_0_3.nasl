#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(12260);
  script_version ("$Revision: 1.13 $");
  script_bugtraq_id(10428);
  script_osvdb_id(38192);

  script_name(english:"Subversion < 1.0.4 Pre-Commit-Hook Remote Overflow");
  script_summary(english:"Subversion Pre-Commit-Hook Vulnerability");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote service is vulnerable to a buffer overflow.'
  );

  script_set_attribute(
    attribute:'description',
    value:'The remote host is reported vulnerable to a remote
overflow.  An attacker, exploiting this hole, would be
given full access to the target machine.  Versions of
Subversion less than 1.0.4 are vulnerable to this attack.'
  );

  script_set_attribute(
    attribute:'solution',
    value:'Upgrade to version 1.0.4 or higher'
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(
    attribute:'see_also',
    value:'http://svn.collab.net/viewvc/svn/branches/1.4.x/CHANGES?view=markup'
  );

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/06/08");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/05/21");
 script_cvs_date("$Date: 2016/12/14 20:33:27 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
  script_family(english:"Misc.");
  script_dependencie("subversion_detection.nasl");
  script_require_ports("Services/subversion");
  exit(0);
}



# start check

port = get_kb_item("Services/subversion");
if ( ! port ) port = 3690;

if (! get_tcp_port_state(port))
	exit(0);

dat = string("( 2 ( edit-pipeline ) 24:svn://host/svn/nessusr0x ) ");

soc = open_sock_tcp(port);
if (!soc)
        exit(0);

r = recv_line(socket:soc, length:1024);

if (! r)
	exit(0);

send(socket:soc, data:dat);
r = recv_line(socket:soc, length:256);

if (! r)
	exit(0);

#display(r);

if (egrep(string:r, pattern:".*subversion-1\.0\.[0-3][^0-9].*"))
{
	security_hole(port);
}

close(soc);
exit(0);
