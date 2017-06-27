#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(14313);
 script_version("$Revision: 1.15 $");

 script_cve_id("CVE-2004-0778");
 script_bugtraq_id(10955);
 script_osvdb_id(8977);
 
 script_name(english:"CVS history.c File Existence Information Disclosure");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote CVS server is affected by an information disclosure
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote CVS server, according to its version number, can be 
exploited by malicious users to gain knowledge of certain system
information.

This behavior can be exploited to determine the existence and 
permissions of arbitrary files and directories on a vulnerable system." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7a576d49" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?66a25c2a" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to CVS 1.11.17 and 1.12.9, or newer." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/20");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/08/16");
 script_cvs_date("$Date: 2011/11/28 21:39:45 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"Logs into the remote CVS server and asks the version");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2011 Tenable Network Security, Inc.");
 script_family(english:"Misc.");
 script_require_ports("Services/cvspserver", 2401);
 script_dependencies("find_service1.nasl", "cvs_pserver_heap_overflow.nasl");
 exit(0);
}

port = get_kb_item("Services/cvspserver");
if(!port) port = 2401;
if(!get_port_state(port)) exit(0);

version = get_kb_item(string("cvs/", port, "/version"));
if(ereg(pattern:".* 1\.([0-9]\.|10\.|11\.([0-9][^0-9]|1[0-6])|12\.[0-8][^0-9]).*", string:version))
     		security_warning(port);
