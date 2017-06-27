#
# This script was written by Scott Adkins <sadkins@cns.ohiou.edu>
#
# See the Nessus Scripts License for details
#


include("compat.inc");

if (description)
{
 script_id(10132);
 script_version ("$Revision: 1.20 $");
 script_cvs_date("$Date: 2013/01/25 01:19:08 $");

 script_name(english:"Kuang2 the Virus Detection");
 script_summary(english:"Checks for Kuang2 the Virus");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is infected by a virus." );
 script_set_attribute(attribute:"description", value:
"Kuang2 the Virus was found.

Kuang2 the Virus is a program that infects all the executables on the 
system, as well as set up a server that allows the remote control of 
the computer.  The client program allows files to be browsed, uploaded, 
downloaded, hidden, etc on the infected machine.  The client program can
also execute programs on the remote machine.

Kuang2 the Virus also has plugins that can be used that allows the 
client to do things to the remote machine, such as hide the icons and 
start menu, invert the desktop, pop up message windows, etc." );
 script_set_attribute(attribute:"see_also", value:"http://vil.mcafee.com/dispVirus.asp?virus_k=10213" );
 script_set_attribute(attribute:"solution", value:
"Disinfect the computer with the latest copy of virus scanning software.
Alternatively, you can find a copy of the virus itself on the net by 
doing an Altavista search.  The virus comes with the server, client and
infector programs.  The client program not only allows you to remotely
control infected machines, but disinfect the  machine the client is 
running on." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

 script_set_attribute(attribute:"plugin_publication_date", value: "2000/02/17");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000-2013 Scott Adkins");

 script_family(english:"Backdoors");

 script_dependencie("find_service1.nasl");
 script_require_ports(17300);

 exit(0);
}

#
# The script code starts here
#

port = 17300;
if (get_port_state(port))
{
    soc = open_sock_tcp(port);
    if (soc) {
	data = recv_line(socket:soc, length:100);
	if(!data)exit(0);
	if ("YOK2" >< data) security_hole(port);
        close(soc);
    }
}
