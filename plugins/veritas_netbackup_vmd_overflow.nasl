#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(20182);
 script_version("$Revision: 1.20 $");
 script_cve_id("CVE-2005-3116");
 script_bugtraq_id(15353);
 script_osvdb_id(20674);

 script_name(english:"VERITAS NetBackup Volume Manager Daemon Buffer Overflow");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of VERITAS NetBackup Volume
Manager that is vulnerable to a remote buffer overflow.  An attacker
may exploit this flaw to execute arbitrary code on the remote host
with the privileges of a local administrator or to disable the remote
service remotely. 

To exploit this flaw, an attacker would need to send a specially
crafted packet to the remote service." );
 script_set_attribute(attribute:"solution", value:
"http://www.symantec.com/business/support/index?page=content&id=TECH44258" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/11/11");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/11/08");
 script_cvs_date("$Date: 2012/12/10 23:37:07 $");
 script_set_attribute(attribute:"patch_publication_date", value: "2005/11/08");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:symantec_veritas:netbackup");
script_end_attributes();
 
 script_summary(english:"Determines if VERITAS NetBackup Volume Manager is vulnerable to an overflow");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2012 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencies("veritas_netbackup_vmd_detect.nasl");
 script_require_keys("VERITAS/NetBackupVolumeManager");
 exit(0);
}

#

include ("byte_func.inc");

string = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA661292220 9 1 1 \n\n\n\n\n\n\n\n\0' + crap (data:"A", length:0x28);

port = get_kb_item ("VERITAS/NetBackupVolumeManager");
if (!get_port_state (port))
  exit (0);

soc = open_sock_tcp (port);
if (!soc)
  exit (0);

send (socket:soc, data:string);
len = recv (socket:soc, length:4, min:4);
if (strlen(len) != 4)
  exit (0);

len = getdword (blob:len, pos:0);
if ( (len <= 0) || (len >= 65535) )
  exit (0);

buf = recv (socket:soc, length:len, min:len);
if (strlen(buf) != len)
  exit (0);

if (egrep (pattern:"^REQUEST ACKNOWLEDGED", string:buf))
  security_hole(port);

