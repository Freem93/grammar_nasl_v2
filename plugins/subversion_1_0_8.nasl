#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(14800);
 script_version("$Revision: 1.13 $");

 script_cve_id("CVE-2004-0749");
 script_bugtraq_id(11243);
 script_osvdb_id(10217);

 script_name(english:"Subversion < 1.0.8 / 1.1.0-rc4 mod_authz_svn Unreadable Path Metadata Information Disclosure");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by an
information disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"You are running a version of Subversion which is older than 1.0.8 or
1.1.0-rc4. 

A flaw exists in older version, in the apache module mod_authz_svn,
which fails to properly restrict access to metadata within unreadable
paths. 

An attacker can read metadata in unreadable paths, which can contain
sensitive information such as logs and paths." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to subversion 1.0.8, 1.1.0-rc4 or newer." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/09/23");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/09/23");
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

if (egrep(string:r, pattern:".*subversion-1\.(0\.[0-7][^0-9]|1\.0-rc[1-3][^0-9]).*"))
{
	security_warning(port);
}

close(soc);
exit(0);
