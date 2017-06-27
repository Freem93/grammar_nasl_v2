#
# (C) Tenable Network Security, Inc.
#

# http://perso.univ-rennes1.fr/bernard.perrot/SSF/index.html
# http://ccweb.in2p3.fr/secur/ssf/


include("compat.inc");

if(description)
{
 script_id(31421);
 script_version ("$Revision: 1.12 $");
 script_cvs_date("$Date: 2014/05/16 22:04:05 $");

 script_name(english: "SSH (SSF Derivative) Detection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote version of the SSH server is not maintained
any more." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the remote SSH server is the
SSF derivative.

SSF had been written to be compliant with restrictive 
laws on cryptography in some European countries, France 
especially. 

These regulations have been softened and OpenSSH received 
a formal authorisation from the French administration in 
2002 and the development of SSF has been discontinued.

SSF is based on an old version of OpenSSH and it implements
an old version of the protocol. As it is not maintained any
more, it might be vulnerable to dangerous flaws." );
 script_set_attribute(attribute:"see_also", value:"http://ccweb.in2p3.fr/secur/ssf/" );
 script_set_attribute(attribute:"see_also", value:"http://perso.univ-rennes1.fr/bernard.perrot/SSF/" );
 script_set_attribute(attribute:"solution", value:
"Remove SSF and install an up-to-date version of OpenSSH." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");

 script_set_attribute(attribute:"plugin_publication_date", value: "2008/03/12");
 script_set_attribute(attribute:"plugin_type", value: "remote");
 script_end_attributes();
 
 script_summary(english: "Look for SSF in the SSH banner");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2008-2014 Tenable Network Security, Inc.");
 script_family(english: "Service detection");
 script_dependencie("ssh_detect.nasl");
 script_require_ports("Services/ssh", 22);
 exit(0);
}

include("global_settings.inc");
include('misc_func.inc');

port = get_kb_item("Services/ssh");
if (! port) port = 22;
if (! get_port_state(port)) exit(0);

banner = get_unknown_banner(port: port);
if (egrep(string: banner, pattern: "^SSH-[0-9.]+-SSF"))
 security_note(port);

