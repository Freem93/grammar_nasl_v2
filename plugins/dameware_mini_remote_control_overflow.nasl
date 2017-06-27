#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(19553);
 script_version("$Revision: 1.20 $");
 script_cvs_date("$Date: 2016/12/06 20:03:50 $");

 script_cve_id("CVE-2003-1030");
 script_bugtraq_id(9213);
 script_osvdb_id(3042);

 script_name(english:"DameWare Mini Remote Control Pre-Authentication Remote Overflow");
 script_summary(english:"Determines version of DameWare Mini Remote Control (Overflow)");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host.");
 script_set_attribute(attribute:"description", value:
"The remote host is running DameWare Mini Remote Control.  The remote
version of this software is affected by a buffer overflow
vulnerability. 

An attacker may be able to exploit this flaw by sending a specially
crafted packet to the remote host. 

A successful exploitation of this vulnerability would result in remote
code execution.");
 script_set_attribute(attribute:"solution", value:
"Upgrade to version 3.73.0.0 or later");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"exploithub_sku", value:"EH-11-317");
 script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");
 script_set_attribute(attribute:"vuln_publication_date", value:"2003/12/16");
 script_set_attribute(attribute:"plugin_publication_date", value:"2005/09/01");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:dameware:mini_remote_control");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
 script_family(english:"Windows");

 script_require_ports(6129, "Services/dameware");
 script_dependencies("find_service2.nasl");
 exit(0);
}

function inverse(data)
{
 local_var tmp, i;

 tmp = NULL;

 for (i=0; i<strlen(data);i++)
    tmp += data[strlen(data)-(i+1)];

 return tmp;
}


function create_mask (size)
{
 local_var mask, i;

 mask = 0;

 for (i=0; i<size; i++)
  mask += 1 << i;

 return mask;
}

function convert_float (float)
{
 local_var exponent, mantissa, major, minor, ret;

 if (ord(float[0]) & 128)
   return NULL;

 exponent = ((ord(float[0]) & 127) << 4) +
            ((ord(float[1]) & 240) >> 4) - 1023;


 if (exponent > 16)
   return NULL;

 mantissa = 65536 +
           ((ord(float[1]) & 15) << 12) +
           ((ord(float[2]) & 255) << 4) +
           ((ord(float[3]) & 240) >> 4);

 major = mantissa >> (16 - exponent);

 minor = mantissa & create_mask(size:16 - exponent);

 ret = NULL;
 ret[0] = major;
 ret[1] = minor;

 return ret;
}



port = get_kb_item("Services/dameware");
if (! port) port = 6129;

if (!get_port_state(port))
  exit(0);

soc = open_sock_tcp(port);
if (!soc)
  exit(0);

buf = recv(socket:soc, length:50);
if (!buf || (strlen(buf) != 40) || (ord(buf[0]) != 0x30) || (ord(buf[1]) != 0x11))
  exit(0);

raw_version = inverse (data:substr(buf,8,15));

version = convert_float (float:raw_version);

if (!isnull(version))
{
 set_kb_item (name:"DameWare/major_version", value:version[0]);
 set_kb_item (name:"DameWare/minor_version", value:version[1]);

 if ((version[0] < 3) || ((version[0] == 3) && (version[1] < 23920)))
   security_hole(port:port);
}
