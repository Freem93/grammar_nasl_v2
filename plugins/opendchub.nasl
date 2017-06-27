#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if(description)
{
 script_id(15834);
 script_version("$Revision: 1.14 $");
 script_cve_id("CVE-2004-1127");
 script_bugtraq_id(11747);
 script_osvdb_id(12137);

 script_name(english:"Open DC Hub RedirectAll Value Remote Overflow");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that may allow arbitrary 
code execution on the remote system." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Open DC Hub, a peer-to-peer file 
sharing application, which is vulnerable to a remote buffer 
overflow. A successful exploit would allow a remote attacker
to execute code on the remote host.

It must be noted that the remote attacker needs administrative 
access to this application." );

 script_set_attribute(attribute:"see_also", value:
"http://lists.grok.org.uk/pipermail/full-disclosure/2004-November/029383.html" );

 script_set_attribute(attribute:"solution", value:
"None at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/11/25");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/11/24");
 script_cvs_date("$Date: 2011/03/11 21:52:37 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Determines if the remote system is running Open DC Hub");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2011 Tenable Network Security, Inc.");
 script_family(english:"Peer-To-Peer File Sharing");
 script_dependencie("find_service1.nasl","find_service2.nasl");
 script_require_ports("Services/DirectConnectHub", "Services/opendchub");
 exit(0);
}

#

port = get_kb_item("Services/DirectConnectHub");
if ( port )
{
  sock = open_sock_tcp (port);
  if ( ! sock ) exit(0);

  data = recv (socket:sock, length:4000);
  if (egrep (pattern:"This hub is running version 0\.([0-6]\.[0-9]+|7\.([0-9][^0-9]|1[0-4])) of Open DC Hub", string:data))
  {
    security_hole(port);
    exit(0);
  }
}
else
{
  port = get_kb_item("Services/opendchub");
  if ( !port ) exit(0);

  sock = open_sock_tcp (port);
  if ( ! sock ) exit(0);

  data = recv (socket:sock, length:4000);
  if (egrep (pattern:"Open DC Hub, version 0\.([0-6]\.[0-9]+|7\.([0-9][^0-9]|1[0-4])), administrators port", string:data))
  {
    security_hole(port);
    exit(0);
  }
}
