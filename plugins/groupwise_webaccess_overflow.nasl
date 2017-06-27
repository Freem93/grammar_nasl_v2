#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25084);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2007-2171");
  script_bugtraq_id(23556);
  script_osvdb_id(35018);
  script_xref(name:"TRA", value:"TRA-2007-01");

  script_name(english:"Novell Groupwise WebAccess GWINTER.EXE Base64 Decoding Remote Overflow");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to execute code on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of GroupWise WebAccess from
Novell that is vulnerable to a stack overflow in the way it handles
HTTP Basic Authentication.

By sending a specially crafted request, an attacker can exploit this
flaw to execute code on the remote host with administrative
privileges.");
 script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2007-01");
 script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-07-015.html");
 script_set_attribute(attribute:"solution", value:
"Upgrade to GroupWise 7.0 SP2 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');

 script_set_attribute(attribute:"plugin_publication_date", value: "2007/04/23");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/04/18");
 script_cvs_date("$Date: 2015/10/07 15:36:47 $");
 script_set_attribute(attribute:"patch_publication_date", value: "2007/04/16");
script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:novell:groupwise_webaccess");
script_end_attributes();

  script_summary(english:"Checks for GroupWise WebAccess version");
  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain a shell remotely");
  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
  script_dependencies("http_version.nasl");
  script_require_ports(7205, 7211);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

# Can't use HTTP function because host must looks like Host: ip:port

ports = make_list(7205, 7211);

foreach port (ports)
{
 if (!get_port_state(port))
   continue;

 req = string(
	"GET / HTTP/1.1\r\n",
	"Host: ", get_host_ip(), ":", port, "\r\n",
	"\r\n"
	);

 soc = open_sock_tcp(port);
 if (!soc)
   continue;

 send(socket:soc, data:req);
 buf = recv (socket:soc, length:4096);

 buf = egrep(pattern:"^Server: GroupWise-WebAccess-Agent/[0-9]+\.[0-9]+\.[0-9]+.*", string:buf);
 if (!buf)
 {
  close(soc);
  continue;
 }
 
 ver = ereg_replace(pattern:"^Server: GroupWise-WebAccess-Agent/([0-9]+\.[0-9]+\.[0-9]+)[^0-9]*", string:buf, replace:"\1");
 ver = split(ver, sep:".", keep:FALSE);

 if ( int(ver[0]) < 7 ||
      (int(ver[0]) == 7 && int(ver[1]) == 0 && int(ver[2]) < 2) )
   security_hole(port);

 close(soc);
}
