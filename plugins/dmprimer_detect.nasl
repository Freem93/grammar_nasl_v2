#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(20745);
 script_version("$Revision: 1.15 $");
 script_cvs_date("$Date: 2011/05/24 20:37:07 $");

 script_name(english:"CA DMPrimer Service Detection");

 script_set_attribute(attribute:"synopsis", value:
"An installation service is running on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host is running the CA DMPrimer service (DM 
Deployment Common Component). 

This service is bundled with products such as BrightStor ARCserve
Backup for Laptops & Desktops, Unicenter Remote Control, CA Protection
Suite, etc..." );
 script_set_attribute(attribute:"see_also", value:"http://supportconnectw.ca.com/public/ca_common_docs/dmdeploysecurity-faqs.asp" );
 script_set_attribute(attribute:"solution", value:
"Filter incoming traffic to this port if you do not use it." );
 script_set_attribute(attribute:"risk_factor", value:"None" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2006/01/19");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Determines if DMPrimer is installed");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2006-2011 Tenable Network Security, Inc.");
 script_family(english:"Service detection");
 script_require_ports(5727);
 exit(0);
}

#

include("global_settings.inc");
include("misc_func.inc");


function decrypt (edata)
{
 local_var length, fb, sb, rl, data, l, var_4, val, cpt, c;

 length = strlen(edata);

 # 2 bytes are needed
 if (length < 2)
   exit (0);

 fb = ord(edata[0]);
 sb = ord(edata[1]);

 rl = length - 2;
 edata = substr (edata, 2, strlen(edata)-1);
  
 if (rl <= 0)
 {
  return NULL;
 }

 sb = (sb * 256) + fb;

 # not crypted
 if (sb == 0)
 {
  data = edata;
 }
 else
 {
  data = NULL;

  if (rl > 2)
    l = (sb % (rl - 2)) + 2;
  else
    l = rl;

  var_4 = sb % 255;
  val = 0;
  cpt = 0;

  while (cpt < rl)
  {
   if ((cpt % l) == 0)
   {
    val = cpt;

    if ((rl - cpt) < l)
      l = rl - cpt;
   }

   c = ord (edata[(val - (cpt % l) + l) - 1]);
   c = (c - (cpt % 255)) - var_4 + 0x1FD;
   c = c % 255;
   c++;

   if (c == 255)
     data += raw_string(0);
   else
     data += raw_string(c);

   cpt++;
  }
 }

 return data;
}

port = 5727;
if (! get_udp_port_state(port)) exit(0, "UDP port "+port+" is not open.");

soc = open_sock_udp (port);
if (!soc)
  exit (0);


request = raw_string (
	0x9D, 0xE8, 0xED, 0xC9, 0xF9, 0xF4, 0xED, 0xE3, 0xDE, 0xFC, 0x9C, 0xCE, 0xF9, 0xE9, 0xDB, 0xBD, 
	0xED, 0xE8, 0xE1, 0xD7, 0xD2, 0xF0, 0x9B, 0xC3, 0xC4, 0xC2, 0xBD, 0xBB, 0xBA, 0xB9, 0xB8, 0xB7, 
	0xB6, 0x06, 0xE9, 0xA7
);

send (socket:soc, data:request);

edata = recv (socket:soc, length:4096);

if (isnull(edata))
  exit (0);

data = decrypt (edata:edata);

if (!isnull (data) &&
    (get_host_ip () >< data) &&
    ("DMPrimer" >< data) &&
    ("_@DMSW&VN_") >< data)
{
 register_service(port:port, ipproto: "udp", proto:"dmprimer");

 data = str_replace (find:'\0', replace:'', string:data);
 version = ereg_replace (pattern:".*_@DMSW&VN_([0-9]+\.[0-9]+\.[0-9]+).*", string:data, replace:"\1");

 report = string ("\n",
		"The remote host is running DMPrimer v", version, ".");

 security_note (port:port, extra:report, proto:"udp");
 set_kb_item (name:"CA/DMPrimer", value:version);
}
