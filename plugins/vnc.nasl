#
# This script was written by Patrick Naubert
# This is version 2.0 of this script.
#
# Modified by Georges Dagousset <georges.dagousset@alert4web.com> :
#	- warning with the version
#	- detection of other version
#	- default port for single test
#
# See the Nessus Scripts License for details
#


include("compat.inc");

if(description)
{
 script_id(10342);
 script_version ("$Revision: 1.22 $");
 script_cvs_date("$Date: 2011/04/01 19:26:04 $");

 script_name(english:"VNC Software Detection");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is running a remote display software (VNC)." );
 script_set_attribute(attribute:"description", value:
"The remote host is running VNC (Virtual Network Computing), which uses
the RFB (Remote Framebuffer) protocol to provide remote access to
graphical user interfaces and thus permits a console on the remote
host to be displayed on another." );
 script_set_attribute(attribute:"see_also", value:"http://en.wikipedia.org/wiki/Vnc" );
 script_set_attribute(attribute:"solution", value:
"Make sure use of this software is done in accordance with your
organization's security policy and filter incoming traffic to this
port." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2000/03/07");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 summary["english"] = "Checks for VNC";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000-2011 Patrick Naubert");
 script_family(english: "Service detection");
 script_dependencie("find_service1.nasl");
 script_require_ports("Services/vnc", 5900, 5901, 5902);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

#
# The script code starts here
#

function probe(port)
{
 local_var match, matches, pat, r, report, ver;

 # if (! get_port_state(port)) return 0;
 r = get_kb_banner(port: port, type: "spontaneous");
 if ( ! r ) return 0;

 pat = "^RFB ([0-9]{3})\.([0-9]{3})";
 matches = egrep(pattern:pat, string:r);
 if (matches)
 {
  foreach match (split(matches))
  {
   match = chomp(match);
   match = match - "RFB ";
   ver = split(match, sep:".", keep:FALSE);

   report = string(
    "\n",
    "The highest RFB protocol version supported by the server is :\n",
    "\n",
    "  ", int(ver[0]), ".", int(ver[1]), "\n"
   );
   security_note(port:port, extra:report);

   break;
  }
 }
}

port = get_kb_item("Services/vnc");
if(port)probe(port:port);
else
{
 for (port=5900; port <= 5902; port = port+1) {
  probe(port:port);
 }
}
