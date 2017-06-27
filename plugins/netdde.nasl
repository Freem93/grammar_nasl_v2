#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(15572);
 script_version("$Revision: 1.28 $");
 script_cvs_date("$Date: 2014/03/31 10:44:06 $");

 script_cve_id("CVE-2004-0206");
 script_bugtraq_id(11372);
 script_osvdb_id(10689);
 script_xref(name:"MSFT", value:"MS04-031");

 script_name(english:"MS04-031: Vulnerability NetDDE Could Allow Code Execution (841533) (uncredentialed check)");
 script_summary(english:"Determines if hotfix 841533 has been installed (Netbios)");

 script_set_attribute(attribute:"synopsis", value:"Arbitrary code can be executed on the remote host.");
 script_set_attribute(attribute:"description", value:
"The remote version of Windows is affected by a vulnerability in Network
Dynamic Data Exchange (NetDDE). 

An attacker may exploit this flaw to execute arbitrary code on the
remote host with the SYSTEM privileges.");
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms04-031");
 script_set_attribute(attribute:"solution", value:"Microsoft has released patches for Windows NT, 2000, XP, and 2003.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'MS04-031 Microsoft NetDDE Service Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/10/12");
 script_set_attribute(attribute:"plugin_publication_date", value:"2004/10/27");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows_2000");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows_2003");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows_98");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows_nt");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows_xp");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2014 Tenable Network Security, Inc.");
 script_family(english:"Windows");

 script_dependencies("netbios_name_get.nasl");
 script_require_ports(139);
 script_require_keys("SMB/name");
 exit(0);
}

#

function netbios_encode(data,service)
{
 local_var tmpdata, ret, i, o, odiv, omod, c;

 ret = "";
 tmpdata = data;

 while (strlen(tmpdata) < 15)
 {
   tmpdata += " ";
 }

 tmpdata += raw_string(service);

 for(i=0;i<16;i=i+1)
 {
   o = ord(tmpdata[i]);
   odiv = o/16;
   odiv = odiv + ord("A");
   omod = o%16;
   omod = omod + ord("A");
   c = raw_string(odiv, omod);

   ret = ret+c;
 }

 return(ret);
}


function smb_recv(socket, length)
{
   local_var header, len, trailer;

   header = recv(socket:socket, length:4, min:4);
   if (strlen(header) < 4)return(NULL);
   len = 256 * ord(header[2]);
   len += ord(header[3]);
   if (len == 0)return(header);
   trailer = recv(socket:socket, length:len, min:len);
   if(strlen(trailer) < len )return(NULL);
   return strcat(header, trailer);
}

function kb_smb_name()
{
 local_var ret;
 ret = get_kb_item("SMB/name");
 if ( ret )
	return string(ret);
 else
	return get_host_ip();
}

function ntol(buffer,begin)
{
 local_var len;

 len = 16777216*ord(buffer[begin+3]) +
       ord(buffer[begin+2])*65536 +
       ord(buffer[begin+1])*256 +
       ord(buffer[begin]);

 return len;
}


function raw_int32(i)
{
 local_var buf;

 buf = raw_string (
		 (i>>24) & 255,
	         (i>>16) & 255,
                 (i>>8) & 255,
                 (i) & 255
		 );
 return buf;
}


function raw_int(i)
{
 local_var buf;

 buf = raw_string (
		 (i) & 255,
                 (i>>8) & 255,
                 (i>>16) & 255,
                 (i>>24) & 255
		 );
 return buf;
}


function checksum(data)
{
 local_var len, chk, i, dlen;

 chk = 0xFFFFFFFF;
 dlen = strlen(data);
 len =  dlen -4;

 for (i=0;i<len;i+=4)
    chk += ntol(buffer:data, begin:i);

 while (i < dlen)
 {
  chk += ord(data[i]);
  i++;
 }

 return raw_int(i:chk);
}


function netbios(data)
{
 return  raw_int32(i:strlen(data)) + data;
}


function netdde(name,host)
{
 local_var lname,rhost,core,len;
 local_var name_hi,name_low,rhost_hi,rhost_low,core_hi,core_low;
 local_var len_low, len_hi;
 local_var main,header,data;

 lname = name + raw_string(0x01);
 rhost = host + raw_string(0x01);
 core = "CORE1.0" + raw_string(0x01);

 #lname length
 len = strlen(lname);
 name_hi = len / 256;
 name_low = len % 256;

 #rhost length
 len = strlen(rhost) + strlen(lname);
 rhost_hi = len / 256;
 rhost_low = len % 256;

 #core length
 len = strlen(core);
 core_hi = len / 256;
 core_low = len % 256;

 main = raw_string(0x01,0x00,0xBE,0x05,0x0A,0x00,0x00,name_hi,name_low,rhost_hi,rhost_low,core_hi,core_low,0x00) + lname + rhost + core + raw_string(0x2E);

 len = strlen(main);
 len_hi = len / 256;
 len_low = len % 256;

 header = raw_string(
 0x45,0x44,0x44,0x4E,0x00,0x00,0x00,
 len_hi,len_low,
 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
 len_hi,len_low,
 0x00,0x00,0x02,0x02,0x00,0x00,0x00,0x01,0x00,0x00,0x00) +
 #raw_string(0x82,0x8D,0xCB,0x3D);
 checksum(data:main);

 data = checksum(data:header) + header + main;

 data += raw_string(0x0d,0x12,0x0b,0x06,0x0d,0x18,0x1c,0x01,0x10,0x03,0x12,0x08,0x1d,0x1f,0x0a,0x0a,0x16,0x02,0x17,0x0e,0x1b,0x0d);

 data += crap(data:raw_string(0x03), length:0x19);

 data = netbios(data:data);

 return data;
}

hname = kb_smb_name();
if ( ! hname ) exit(0);

port = 139;
if ( ! get_port_state(port) ) exit(0);
soc = open_sock_tcp(port);
if ( ! soc ) exit(0);


session_request = raw_string(0x81, 0x00, 0x00, 0x44) +
		  raw_string(0x20) +
		  netbios_encode(data:hname, service:0x1F) +
                  raw_string(0x00, 0x20) +
		  "CACACACACACACACACACACACACACACABP" +
		  raw_string(0x00);

send(socket:soc, data:session_request);
r = smb_recv(socket:soc, length:4000);
if ( ! r ) exit(0);

if(ord(r[0])!=0x82)
 exit(0);

data = netdde(name:"NESSUS", host:hname);

send(socket:soc, data:data);
r = smb_recv(socket:soc, length:4000);

if (!r && (strlen(r) < 12))
  exit(0);

chk = substr(r,8,11);

if( "EDDN" >< chk)
{
 security_hole(port);
 exit(0);
}
