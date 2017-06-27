#
# (C) Tenable Network Security, Inc.
#

# Ref:
#
# Date: 27 Mar 2003 15:31:41 -0000
# From: Arhont Information Security <infosec@arhont.com>
# To: bugtraq@securityfocus.com
# Subject: SNMP security issues in D-Link DSL Broadband Modem/Router


include("compat.inc");

if (description)
{
  script_id(11490);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2016/12/14 20:33:26 $");

  script_bugtraq_id(7212);
  script_osvdb_id(58147, 58148);

  script_name(english:"D-Link DSL Broadband Modem SNMP Cleartext ISP Credential Disclosure");
  script_summary(english:"Enumerates user and password via SNMP");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote host has a well known default username and password.'
  );
  script_set_attribute(
    attribute:'description',
    value:
'This script uses SNMP to obtain the account and password of the remote
ADSL connection.  D-Link DSL Broadband routers uses a default community
string and stores the ISP credentials in cleartext.'
  );
  script_set_attribute(attribute:'solution', value:'Filter access to SNMP on this device.');
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:'see_also', value:'http://seclists.org/bugtraq/2003/Mar/401');

  script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
  script_family(english:"SNMP");

  script_dependencie("snmp_default_communities.nasl");
  script_require_keys("SNMP/community");
  exit(0);
}


include("global_settings.inc");

exit(0); # Broken
if ( ! experimental_scripts ) exit(0);

#
# Solaris comes with a badly configured snmpd which
# always reply with the same value. We make sure the answers
# we receive are not in the list of default values usually
# answered...
#
function valid_snmp_value(value)
{
 if("/var/snmp/snmpdx.st" >< value)return(0);
 if("/etc/snmp/conf" >< value)return(0);
 if( (strlen(value) == 1) && (ord(value[0]) < 32) )return(0);
 return(1);
}

#--------------------------------------------------------------------#
# Forges an SNMP GET NEXT packet                                     #
#--------------------------------------------------------------------#
function get_next(community, id, object)
{
 local_var _r, a_len, len, o_len, tot_len;

 len = strlen(community);
#display("len : ", len, "\n");
 len = len % 256;

 tot_len = 4 + strlen(community) + 12 + strlen(object) + 4;
# display(hex(tot_len), "\n");
 _r = raw_string(0x30, tot_len, 0x02, 0x01, 0x00, 0x04, len);
 o_len = strlen(object) + 2;

 a_len = 13 + strlen(object);
 _r = _r + community + raw_string( 0xA1,
	a_len, 0x02, 0x01, id,   0x02, 0x01, 0x00, 0x02,
	0x01, 0x00, 0x30,o_len) + object + raw_string(0x05, 0x00);
# display("len : ", strlen(_r), "\n");
 return(_r);
}



community = get_kb_item("SNMP/community");
if(!community)exit(0);

ifaces = "";

port = get_kb_item("SNMP/port");
if(!port)port = 161;
if (! get_udp_port_state(port)) exit(0, "UDP port "+port+" is not open.");

soc = open_sock_udp(port);

first = raw_string(0x30, 0x11, 0x06,
		   0x0D, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x0A, 0x17,
		   0x02, 0x03, 0x01, 0x05, 0x02, 0x1);

id = 2;
req = get_next(id:id, community:community, object:first);

send(socket:soc, data:req);
r = recv(socket:soc, length:1025);
close(soc);
if(strlen(r) < 48)exit(0);

username = NULL;

len = strlen(r);
if(ord(r[2]) == 0x02)
{
 start = 34 + strlen(community);
}
else
{
start = 38 + strlen(community);
}

for(i=start;i<len;i=i+1)
{
  if( (ord(r[i]) >= 10) && (ord(r[i]) <= 127) )
     username += r[i];
}

if(valid_snmp_value(value:username))
{
	soc = open_sock_udp(port);

	first = raw_string(0x30, 0x11, 0x06,
		   0x0D, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x0A, 0x17,
		   0x02, 0x03, 0x01, 0x06, 0x02, 0x1);

	id = 3;
	req = get_next(id:id, community:community, object:first);
	send(socket:soc, data:req);
	r = recv(socket:soc, length:1025);
	close(soc);
	if(strlen(r) < 48)exit(0);

	len = strlen(r);
	if(ord(r[2]) == 0x02)
	{
 		start = 34 + strlen(community);
	}
	else
	{
		start = 38 + strlen(community);
	}

	password = NULL;
	for(i=start;i<len;i=i+1)
	{
 	 if( (ord(r[i]) >= 10) && (ord(r[i]) <= 127) ) password += r[i];
	}

	if(valid_snmp_value(value:password))
	{
 	 report = "
Using SNMP, it was possible to determine the login/password pair of what
is likely to be the remote ADSL connection : '" + username +"'/'" + password;

	security_hole(port:port, proto:"udp", extra:report);
	}
}
