#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(14315);
 script_version("$Revision: 1.9 $");
 script_cvs_date("$Date: 2011/11/28 21:39:45 $");

 script_name(english:"Cfengine Detection and Local Identification");
 
 script_set_attribute(attribute:"synopsis", value:
"The cfengine service is running on this port.");
 script_set_attribute(attribute:"description", value:
"Cfengine is a language-based system for testing and configuring
Unix and Windows systems attached to a TCP/IP network." );
 script_set_attribute(attribute:"see_also", value:"http://www.cfengine.org/" );
 script_set_attribute(attribute:"solution", value:
"N/A" );
 script_set_attribute(attribute:"risk_factor", value:
"None" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/20");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"check for the presence of cfengine with local identification version checks if possible");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2011 Tenable Network Security, Inc.");
 script_family(english:"Service detection");
 script_require_ports(5308);

 if ( defined_func("bn_random") ) script_dependencies("ssh_get_info.nasl");
 exit(0);
}


port = 5308;

if ( ! get_port_state(port) ) exit(0);

soc = open_sock_tcp(port);
if ( ! soc ) exit(0);


ver = get_kb_item("cfengine/version");
if ( ! ver ) exit(0);


set_kb_item(name:"cfengine/running", value:TRUE);

report = string(
  "\n",
  "Version   : ", ver, "\n"
);

security_note(port:port, extra:report);
