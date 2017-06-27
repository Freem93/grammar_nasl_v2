#
# This script was written by Thomas reinke <reinke@securityspace.com>
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - description moved, bugfix [RD]
# - Revised plugin title, added OSVDB ref (8/6/09)


include("compat.inc");

if(description)
{
 script_id(10948);
 script_version ("$Revision: 1.16 $");
 script_cve_id("CVE-2001-1046");
 script_bugtraq_id(2811);
 script_osvdb_id(776);

 script_name(english:"Qpopper .qpopper-options Username Handling Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote mail server is affected by a remote buffer overflow
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote Qpopper server, according to its banner, is running version
4.0.3 or version 4.0.4.  These versions are vulnerable to a buffer
overflow if they are configured to allow the processing of a user's 
~/.qpopper-options file.  A local user can cause a buffer overflow by 
setting the 'bulldir' variable to something longer than 256 characters.

*** This test could not confirm the existence of the
*** problem - it relied on the banner being returned." );
 # https://web.archive.org/web/20020220095916/http://archives.neohapsis.com/archives/linux/caldera/2001-q3/0006.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e8c930d6" );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2002/05/02");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/04/20");
 script_cvs_date("$Date: 2016/11/02 14:37:08 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"Qpopper options buffer overflow");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2002-2016 Thomas Reinke");
 script_family(english:"Misc.");
 script_dependencie("find_service1.nasl");
 script_require_ports("Services/pop3", 110);
 exit(0);
}

#
# The script code starts here
#

port = get_kb_item("Services/pop3");
if(!port)port = 110;

banner = get_kb_item(string("pop3/banner/", port));
if(!banner)
{
    if(get_port_state(port))
    {
	soc = open_sock_tcp(port);
	if(!soc)exit(0);
	banner = recv_line(socket:soc, length:4096);
    }
}

if(banner)
{
  
    if(ereg(pattern:".*Qpopper.*version (4\.0\.[34]).*", string:banner, icase:TRUE))
    {
	security_hole(port);
    }
}
exit(0);
