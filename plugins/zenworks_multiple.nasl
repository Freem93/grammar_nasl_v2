#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(18524);
 script_version("$Revision: 1.17 $");
 script_cve_id("CVE-2005-1543");
 script_bugtraq_id(13678);
 script_osvdb_id(16698);

 script_name(english:"Novell ZENworks Multiple Remote Pre-Authentication Overflows");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Novell ZENworks Desktop or Server Management,
a remote desktop management software.

The remote version of this software is affected by multiple heap and
stack overflow vulnerabilities which may be exploited by an attacker
to to execute arbitrary code on the remote host with SYSTEM
privileges." );
 script_set_attribute(attribute:"solution", value:
"http://support.novell.com/cgi-bin/search/searchtid.cgi?/10097644.htm" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'Novell ZENworks 6.5 Desktop/Server Management Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/06/17");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/05/19");
 script_cvs_date("$Date: 2011/03/11 21:52:42 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_summary(english:"Determines if ZENWorks is vulnerable to Buffer and Heap Overflow");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");
 script_family(english:"Gain a shell remotely");
 script_require_ports(1761);
 exit(0);
}

port = 1761;

if ( ! get_port_state(port) ) exit(0);

soc = open_sock_tcp (port);
if (!soc) exit(0);

version_req = raw_string (0x00, 0x06, 0x05, 0x01, 0x10, 0xe6, 0x01, 0x00, 0x34, 0x5a, 0xf4, 0x77, 0x80, 0x95, 0xf8, 0x77);

send (socket:soc, data:version_req);
buf = recv (socket:soc, length:20);
if ((strlen(buf) != 16))
  exit(0);

vers = ord (buf[1]);

if ( (vers != 6) &&
     (vers != 4) &&
     (vers != 3) )
  exit (0);

vers_comp = raw_string (0x00, 0x01);

send (socket:soc, data:vers_comp);
buf = recv (socket:soc, length:2);

#must be 0 or 2
if (strlen (buf) == 1)
  exit (0);

# we receive a msg first (sometimes)
if (strlen(buf) == 2)
{
 len = ord(buf[0]) * 256 + ord(buf[1]);
 buf = recv (socket:soc, length:len);
 if (strlen(buf) != len)
   exit(0);
}

auth_req = raw_string(0x02, 0x03) + crap(data:"A", length:0x203) + raw_string(0x00, 0x05) + "ak6lb" + raw_string(0x00, 0x07) + "UNKNOWN" + raw_string (0x00, 0x06);
send (socket:soc, data:auth_req);
buf = recv (socket:soc, length:100);

#server / desktop
rep1 = raw_string(0xff,0x9b);
rep2 = raw_string(0x00,0x00);
rep3 = raw_string(0x00,0x01);

if ((strlen(buf) == 2) && ((rep1 >< buf) || (rep2 >< buf) || (rep3 >< buf)))
  security_hole(port);

