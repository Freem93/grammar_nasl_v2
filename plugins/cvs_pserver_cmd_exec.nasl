#  
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(11970);
 script_version ("$Revision: 1.14 $");
 script_bugtraq_id(9306);
 script_osvdb_id(6429);
 
 script_name(english:"CVS PServer CVSROOT Passwd File Arbitrary Code Execution");
 script_summary(english:"Logs into the remote CVS server and asks the version");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote version control service has a code execution vulnerability."
 );
 script_set_attribute(attribute:"description", value:
"According to its version number, the remote CVS server has an
arbitrary code execution vulnerability.  Any user with the ability to
write the CVSROOT/passwd file could execute arbitrary code as root." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.nessus.org/u?b3bb9c46"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to CVS 1.11.11 or later."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/01/01");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/12/18");
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
if ( ! version ) exit(0);
if(ereg(pattern:".* 1\.([0-9]\.|10\.|11\.([0-9][^0-9]|10)).*", string:version))
     	security_hole(port);
