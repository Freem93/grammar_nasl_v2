#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(11755);
 script_version ("$Revision: 1.28 $");

 script_cve_id("CVE-2001-0826", "CVE-2001-1335", "CVE-2001-1336", "CVE-2003-0329", "CVE-2004-0298", "CVE-2006-2961");
 script_bugtraq_id(2785, 2786, 2972, 7946, 7950, 9666, 18586);
 script_osvdb_id(3999, 8982, 9399, 12056, 12057, 26364);
 
 script_name(english:"CesarFTP Multiple Vulnerabilities (OF, File Access, more)");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by multiple flaws." );
 script_set_attribute(attribute:"description", value:
"The remote host is running CesarFTP, an FTP server for Windows systems. 

There are multiple flaws in this version of CesarFTP that could allow
an attacker to execute arbitrary code on this host, or simply to
disable this server remotely." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2001/May/248" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6734d8ec" );
 script_set_attribute(attribute:"see_also", value:"http://www.securiteam.com/exploits/5ZP0C0AIUA.html" );
 script_set_attribute(attribute:"solution", value:
"Remove the software as it has not been updated since 2002." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'Cesar FTP 0.99g MKD Command Buffer Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/06/18");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/05/28");
 script_cvs_date("$Date: 2016/10/07 13:30:47 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"CesarFTP overflows");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
 script_family(english:"FTP");
 script_dependencie("ftpserver_detect_type_nd_version.nasl");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here
#

include("ftp_func.inc");
include("global_settings.inc");


port = get_ftp_port(default: 21);

banner = get_ftp_banner(port:port);
if (
  banner && 
  egrep(pattern:"^220 CesarFTP 0\.([0-8]|9[0-8]|99[a-g])", string:banner)
)
{
  security_hole(port);
  exit(0);
}


# Ferdy Riphagen pointed out that while the banne can be tweaked, the
# help command can not be.
if (thorough_tests)
{
  soc = open_sock_tcp(port);
  if (soc) {
    ftp_send_cmd(socket:soc, cmd:"HELP");
    res = recv(socket:soc, length:1024);
    ftp_close(socket:soc);

    if (
      res && 
      egrep(pattern:"CesarFTP server 0\.([0-8]|9[0-8]|99[a-g])", string:res)
    ) security_hole(port);
  }
}
exit(0);

#
# The following code freezes the GUI, but does not
# crash the FTP daemon
# 
# send(socket:soc, data:'USER !@#$%^&*()_\r\n');
# r = ftp_recv_line(socket:soc);
# display(r);
# send(socket:soc, data:'USER ' + crap(256) + '\r\n');
# r = ftp_recv_line(socket:soc);
# display(r);
