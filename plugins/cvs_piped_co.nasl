#  
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(12212);
 script_version ("$Revision: 1.15 $");
 script_cve_id("CVE-2004-0405");
 script_bugtraq_id(10140);
 script_osvdb_id(5366);
 
 script_name(english:"CVS Client Traversal Arbitrary File Retrieval");
 script_summary(english:"Logs into the remote CVS server and asks the version");
 
 script_set_attribute(attribute:"synopsis",value:
"The remote version control service has a directory traversal vulnerability." );
 script_set_attribute(attribute:"description", value:
"According to its version number, the remote CVS server has a directory
directory traversal vulnerability.  This could allow a malicious
client to read files outside of the CVS root." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.openbsd.org/errata35.html#cvs"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to CVS 1.11.15 / 1.12.7 or later."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/04/16");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/04/15");
 script_cvs_date("$Date: 2011/03/21 15:22:43 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Misc.");

 script_copyright(english:"This script is Copyright (C) 2004-2011 Tenable Network Security, Inc.");
 script_require_ports("Services/cvspserver", 2401);
 script_dependencies("find_service1.nasl", "cvs_pserver_heap_overflow.nasl");

 exit(0);
}

include('global_settings.inc');

port = get_kb_item("Services/cvspserver");
if(!port)port = 2401;
if(!get_port_state(port))exit(0);

version = get_kb_item(string("cvs/", port, "/version"));
if(ereg(pattern:".* 1\.([0-9]\.|10\.|11\.([0-9][^0-9]|1[0-4])|12\.[0-6][^0-9]).*", string:version))
     	security_warning(port);
