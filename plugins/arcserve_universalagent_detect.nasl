#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(18040);
 script_version("$Revision: 1.11 $");
 script_cvs_date("$Date: 2014/01/07 21:38:30 $");

 script_name(english:"CA ARCServe UniversalAgent Detection");
 script_summary(english:"Determine if a remote host is running BrightStor ARCServe UniversalAgent");

 script_set_attribute(attribute:"synopsis", value:"A backup software is running on the remote port.");
 script_set_attribute(attribute:"description", value:
"The remote host is running the BrightStor ARCServe UniversalAgent on this
port.");
 script_set_attribute(attribute:"solution", value:
"If this service is not needed, disable it or filter incoming traffic
to this port.");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2005/04/13");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Service detection");
 script_copyright(english:"This script is Copyright (C) 2005-2014 Tenable Network Security, Inc.");
 script_require_ports (6050);
 exit(0);
}

include ('byte_func.inc');

function get_string (blob, pos)
{
 local_var tmp, len, i;

 len = strlen (blob);
 tmp = "";

 for (i=pos; i<len; i++)
   if (blob[i] == '\0')
     return tmp;
   else
     tmp += blob[i];

 return tmp;
}


port = 6050;
if (!get_port_state(port)) exit(0);
soc = open_sock_tcp (port);
if (!soc) exit(0);

data = raw_string (0x00,0x00,0x00,0x00,0x03,0x20,0xBC,0x02);
data += crap (data:"2", length:256);
data += crap (data:"A", length:20);
data += raw_string (0x0B, 0x11, 0x0B, 0x0F, 0x03, 0x0E, 0x09, 0x0B,
                    0x16, 0x11, 0x14, 0x10, 0x11, 0x04, 0x03, 0x1C,
                    0x11, 0x1C, 0x15, 0x01, 0x00, 0x06);
data += crap (data:"A", length:402);

send (socket:soc, data:data);
ret = recv (socket:soc, length:4096);

close (soc);

if ((strlen(ret) == 8) && ( "0000730232320000" >< hexstr(ret) ))
{
 set_kb_item (name:"ARCSERVE/UniversalAgent", value:TRUE);

 report = NULL;

 soc = open_sock_tcp (port);
 if (soc)
 {
  data = raw_string (0x00,0x00,0x0D,0x00,0x03,0x20,0xBC,0x02);
  send (socket:soc, data:data);
  ret = recv (socket:soc, length:10000);

  len = strlen (ret);
  if (len > 8)
  {
   dlen = getword (blob:ret, pos:6);
   if (dlen == 0x404)
   {
    os = get_string (blob:ret, pos:8);
    level = get_string (blob:ret, pos:0x109);
    version = get_string (blob:ret, pos:0x20A);
    cpu = get_string (blob:ret, pos:0x30B);

    report = string (
		"It was possible to obtain the following information :\n",
		"OS: ", os, "\n",
		"Level: ", level, "\n",
		"Version: ", version, "\n",
		"CPU: ", cpu, "\n");
   }
  }
 }

 security_note (port:port, extra:report);
}
