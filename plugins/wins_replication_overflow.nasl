#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15970);
  script_version("$Revision: 1.28 $");
  script_cvs_date("$Date: 2016/11/29 20:13:38 $");

  script_cve_id("CVE-2004-0567", "CVE-2004-1080");
  script_bugtraq_id(11763, 11922);
  script_osvdb_id(12370, 12378);
  script_xref(name:"MSFT", value:"MS04-035");
  script_xref(name:"MSFT", value:"MS04-045");

  script_name(english:"MS04-035: WINS Code Execution (870763) (uncredentialed check)");
  script_summary(english:"Determines if hotfix 870763 has been installed");

  script_set_attribute(attribute:"synopsis", value:"Arbitrary code can be executed on the remote host.");
  script_set_attribute(attribute:"description", value:
"The remote Windows Internet Naming Service (WINS) is vulnerable to a
flaw that could allow an attacker to execute arbitrary code on this
host.

To exploit this flaw, an attacker needs to send a specially crafted
packet on port 42 of the remote host.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms04-045");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Windows NT, 2000 and 2003.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'MS04-045 Microsoft WINS Service Memory Overwrite');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/12/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
  script_family(english:"Windows");

  script_dependencies("netbios_name_get.nasl");
  script_require_ports(42);
  exit(0);
}

#

include("byte_func.inc");
port = 42;
if ( ! get_port_state(port) ) exit(0, "WINS server is not running");

soc = open_sock_tcp(port);
if ( ! soc ) exit(0, "WINS server is not running");

request = raw_string (0x00,0x00,0x00,0x29,0x00,0x00,0x78,0x00,0x00,0x00,0x00,0x00,
		      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x02,0x00,0x05,
	    	      0x00,0x00,0x00,0x00,0x60,0x56,0x02,0x01,0x00,0x1F,0x6E,0x03,
	    	      0x00,0x1F,0x6E,0x03,0x08,0xFE,0x66,0x03,0x00);

send(socket:soc, data:request);


r = recv(socket:soc, length:4);
if (!r || strlen(r) != 4 ) exit (0, "WINS server shut the connection down");
len = getdword(blob:r, pos:0);
if ( len > 256 ) exit(1, "Invalid WINS reply");
r += recv(socket:soc, length:len);

if (strlen(r) < 20) exit (1, "Invalid WINS reply");

if (ord(r[6]) != 0x78) exit (1, "Invalid WINS reply");

pointer = substr(r,16,19);

request = raw_string (0x00,0x00,0x00,0x0F,0x00,0x00,0x78,0x00) + pointer + raw_string(
		      0x00,0x00,0x00,0x03,0x00,0x00,0x00,0x00);

send(socket:soc, data:request);

r = recv(socket:soc, length:4);
if (!r || strlen(r) != 4 ) exit (0, "WINS server is patched");
len = getdword(blob:r, pos:0);
if ( len > 256 ) exit(1, "Invalid WINS reply");
r += recv(socket:soc, length:len);

if (strlen(r) < 8) exit (0, "WINS server is patched");

if (ord(r[6]) == 0x78)
  security_hole(port);
else
  exit(0, "WINS server is patched");
