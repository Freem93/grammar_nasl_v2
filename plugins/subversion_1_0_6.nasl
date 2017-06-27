#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(13848);
 script_version("$Revision: 1.15 $");

 script_cve_id("CVE-2004-1438");
 script_bugtraq_id(10800);
 script_osvdb_id(8239);

 script_name(english:"Subversion < 1.0.6 mod_authz_svn Restricted File Access Bypass");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that may allow access to
restricted files." );
 script_set_attribute(attribute:"description", value:
"You are running a version of Subversion which is older than 
1.0.6.

A flaw exists in older version, in the apache module mod_authz_svn.
An attacker can access to any file in a given subversion repository,
no matter what restrictions have been set by the administrator." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to subversion 1.0.6 or newer." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/07/27");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/07/26");
 script_cvs_date("$Date: 2011/11/28 21:39:46 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Check for Subversion version");
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

if (egrep(string:r, pattern:".*subversion-1\.0\.[0-5][^0-9].*"))
{
	security_warning(port);
}

close(soc);
exit(0);
