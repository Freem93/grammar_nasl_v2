# 
# (C) Tenable Network Security, Inc.
#

# Credit:
# From: Joe Stewart <jstewart@lurhq.com>
# To: TH-Research
# Subject: [TH-research] Bagle remote uninstall
# Date: Tue, 20 Jan 2004 17:19:41 -0500
#


include("compat.inc");


if(description)
{
 script_id(12027);
 script_version("$Revision: 1.18 $");

 script_name(english:"Bagle Worm Removal");
 script_summary(english:"Removes Bagle if it is installed");

 script_set_attribute(
   attribute:"synopsis",
   value:"Nessus attempted to remove a worm on the remote host."
 );
 script_set_attribute(attribute:"description",  value:
"The remote host had the Bagle worm installed. Nessus attempted to
remove it by connecting to port 6777 of the host and using the
built-in removal command.  However, you should verify that :

- The worm was removed properly

- The remote host has not been altered in any other way." );
 script_set_attribute(
   attribute:"solution", 
   value:"Verify that the system is clean, and reinstall if necessary."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/01/21");
 script_cvs_date("$Date: 2012/09/24 21:59:12 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2004-2012 Tenable Network Security, Inc.");
 script_family(english:"Backdoors");
 script_require_ports(6777);
 exit(0);
}

#

if ( ! get_port_state(6777) ) 
	exit(0);


soc = open_sock_tcp(6777);
if ( soc )
{
 send(socket:soc, data:raw_string(0x43, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x04) + "12" + raw_string(0));
 r = recv(socket:soc, length:4096);
 #display(hexstr(r), "\n");
 if ( hexstr(r) == "01000000791a0000" ) security_hole(6777);
 close(soc);
}

