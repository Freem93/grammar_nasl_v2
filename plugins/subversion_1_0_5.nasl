#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(12284);
 script_version("$Revision: 1.12 $");

 script_cve_id("CVE-2004-0413");
 script_bugtraq_id(10519);
 script_osvdb_id(6935);
 script_xref(name:"GLSA", value:"GLSA 200406-07");
 script_xref(name:"SuSE", value:"SUSE-SA:2004:018");

 script_name(english:"Subversion < 1.0.5 svnserver svn:// Protocol Handler Remote Overflow");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by a
heap overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"A remote overflow exists in Subversion. svnserver fails to validate 
svn:// requests resulting in a heap overflow. With a specially 
crafted request, an attacker can cause arbitrary code execution 
resulting in a loss of integrity." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to version 1.0.5 or newer." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");


 script_set_attribute(attribute:"plugin_publication_date", value: "2004/06/22");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/06/12");
 script_cvs_date("$Date: 2011/11/28 21:39:46 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Subversion SVN Protocol Parser Remote Integer Overflow");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2011 Tenable Network Security, Inc.");
 script_family(english:"Misc.");
 script_dependencie("subversion_detection.nasl");
 script_require_ports("Services/subversion");
 exit(0);
}



# start check
# mostly horked from MetaSploit Framework subversion overflow check

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

if (egrep(string:r, pattern:".*subversion-1\.0\.[0-4][^0-9].*"))
{
	security_hole(port);
}

close(soc);
exit(0);
