#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(12219);
 script_version ("$Revision: 1.16 $");
 script_cvs_date("$Date: 2013/01/25 01:19:10 $");

 name["english"] = "Sasser Virus Detection";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is infected by a virus." );
 script_set_attribute(attribute:"description", value:
"The Sasser worm is infecting this host.  Specifically,
a backdoored command server may be listening on port 9995 or 9996
and an ftp server (used to load malicious code) is listening on port 
5554 or 1023.  There is every indication that the host is currently 
scanning and infecting other systems." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3245f88a" );
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms04-011" );
 script_set_attribute(attribute:"solution", value:
"Use an antivirus to clean the host." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");


 script_set_attribute(attribute:"plugin_publication_date", value: "2004/05/01");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 summary["english"] = "Sasser Virus Detection";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");
 family["english"] = "Backdoors";
 script_family(english:family["english"]);
 script_require_ports(5554);
 exit(0);
}

# start script

include("ftp_func.inc");
login = "anonymous";
pass  = "bin";

# there really is no telling how many Sasser variants there will be :<
ports[0] =  5554;           
ports[1] =  1023;

foreach port ( ports)
{
 if ( get_port_state(port) )
   {
        soc = open_sock_tcp(port);
        if (soc) 
        {
            if(ftp_authenticate(socket:soc, user:login, pass:pass)) security_hole(port);
	    close(soc);
        }
    }
}





