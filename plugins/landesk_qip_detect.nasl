#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(34235);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2013/12/19 23:04:05 $");

  script_name(english:"LANDesk QIP Server Detection");
  script_summary(english:"Detects a landesk qip service");

 script_set_attribute(attribute:"synopsis", value:
"An asset management agent is listening on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote service is a LANDesk QIP Server, one of the components of
LANDesk Management Suite." );
 # http://web.archive.org/web/20090503002610/http://www.landesk.com/SolutionServices/product.aspx?id=716
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ae87ac86" );
 script_set_attribute(attribute:"solution", value:
"Filter incoming traffic to this port." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/09/17");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_copyright(english:"This script is Copyright (C) 2008-2013 Tenable Network Security, Inc.");

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_require_ports(12175);
  exit(0);
}


include ("global_settings.inc");
include ("misc_func.inc");
include ("byte_func.inc");

function checksum(data, len)
{
 local_var ck;
 local_var i, j;

 ck = 0;
 j = 0;

 for (i=0; i<(len/2); i++)
 {
    ck += ord(data[j]) + (ord(data[j+1]) << 8);
    j += 2;
 }

 if (len % 2) 
   ck += ord(data[j]);

 ck = (ck & 0xffff) + (ck >> 16);
 ck = (ck & 0xffff) + (ck >> 16);

 return ~ck;
}


port = 12175;

if (!get_port_state(port)) exit(0);

soc = open_sock_tcp(port);
if (!soc) exit(0);

set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);

data = "nessus";

data = 
     'heal' +
     mkdword(strlen(data) + 0x24) +
     mkdword(0) +
     mkdword(0) +
     mkdword(0) +
     mkdword(0x24) +  # str offset 1
     mkdword(0x24) +  # str offset 2
     mkdword(0x24) +  # str offset 3
     mkdword(0x24) +  # str offset 4
     data;

set_byte_order(BYTE_ORDER_BIG_ENDIAN);

len = strlen(data);

target_id = 0;

header = 
       mkword(target_id) +
       mkword(checksum(data:data, len:len)) +
       mkword(len) ;

len = strlen(header) + len;

req = 
      "sdfx" +
      mkdword(len + 8) +
      header +
      data;

send(socket:soc, data:req);
buf = recv(socket:soc, length:4096);

if (strlen(buf) != 12) exit(0);

tag = substr(buf, 0, 3);
len = getdword(blob:buf, pos:4);
code = getdword(blob:buf, pos:8);

if (tag == 'sdfx' && len == 12 && code == 0)
{
 register_service(port:port, proto:"landesk-qip");
 security_note(port);
}
