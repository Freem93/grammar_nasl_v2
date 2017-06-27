#
# (C) David Lodge 13/08/2007
# This script is based on sybase_blank_password.nasl which is (C) Tenable Network Security, Inc.
#
# This script is released under the GPLv2
#

# Changes by Tenable:
# - Revised plugin title (6/12/09)


include("compat.inc");

if(description)
{
 script_id(25926);
 script_version ("$Revision: 1.7 $");
 script_cvs_date("$Date: 2013/01/25 01:19:10 $");

 script_name(english:"Sybase ASA Client Connection Broadcast Remote Information Disclosure");
 script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by an information disclosure
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote Sybase SQL Anywhere / Adaptive Server Anywhere database is
configured to listen for client connection broadcasts, which allows an
attacker to see the name and port that the Sybase SQL Anywhere /
Adaptive Server Anywhere server is running on." );
 script_set_attribute(attribute:"see_also", value:"http://www.sybase.com/products/databasemanagement/sqlanywhere" );
 script_set_attribute(attribute:"solution", value:
"Switch off broadcast listening via the '-sb' switch when starting
Sybase." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

 script_set_attribute(attribute:"plugin_publication_date", value: "2007/08/22");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Locate service enabled on Sybase server");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2007-2013 David Lodge");
 script_family(english:"Databases");

 exit(0);
}

#
# The script code starts here
#
include("misc_func.inc");

port = 2638;
if (!get_udp_port_state(port)) exit(0);

req = raw_string(
   0x1b, 0x00, 0x00, 0x39, 0x00, 0x00, 0x00, 0x00, 0x12,
   "CONNECTIONLESS_TDS",
   0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x04, 0x00, 0x02, 0x00,
   0x04, 0x00, 0x00, 0x01, 0x02, 0x00, 0x00, 0x03, 0x01, 0x01,
   0x04, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
);

soc = open_sock_udp(port);
if(soc)
{
   send(socket:soc, data:req);
   r  = recv(socket:soc, length:4096);
   close(soc);
   if(!r)exit(0);
 
   name="";
   length=ord(r[0x27]);
   for (i=0x28;i<0x27+length;i++)
   {
      name+=r[i];
   }

   offset=0x27+length+3;
   serverport=ord(r[offset])*256+ord(r[offset+1]);

   report = string("\n",
     "Database name: ",name, "\n",
     "Database port: ", serverport,"\n");

   security_warning(port:port, protocol:"udp", extra:report);
}
