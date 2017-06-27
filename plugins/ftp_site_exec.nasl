#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10090);
 script_bugtraq_id(2241);
 script_osvdb_id(77, 8719, 8720);
 script_version ("$Revision: 1.35 $");
 script_cve_id("CVE-1999-0080",
 	 	"CVE-1999-0955"  # If vulnerable to the flaw above, it's 
				 # automatically vulnerable to this one
				 # too...
		 
		 );
 script_name(english:"WU-FTPD SITE EXEC Arbitrary Local Command Execution");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by a command execution
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of WU-FTPD that is affected by a
command execution vulnerability. It is possible to execute arbitrary
command son the remote host using the 'site exec' FTP problem." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/1995/Jul/0");
 script_set_attribute(attribute:"solution", value:
"Upgrade to WU-FTPD 2.4 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:ND");

 script_set_attribute(attribute:"plugin_publication_date", value: "1999/06/22");
 script_set_attribute(attribute:"vuln_publication_date", value: "1993/03/01");
 script_cvs_date("$Date: 2016/09/26 16:00:41 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_summary(english:"Attempts to write on the remote root dir");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 1999-2016 Tenable Network Security, Inc.");
 script_family(english:"FTP");
 script_dependencie("ftpserver_detect_type_nd_version.nasl", "ftp_anonymous.nasl");
 script_require_keys("ftp/login");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("ftp_func.inc");
include("http_misc_func.inc");

login = get_kb_item_or_exit("ftp/login");
password = get_kb_item("ftp/password");

cmd = make_array(
'set',	'RE:PATH=[./:]|^path[ \t]+\\([./].*\\)|HOME=/|home[ \t]+/',
'/bin/id', 'RE:uid=[0-9]',
'/usr/bin/id', 'RE:uid=[0-9]'
);

port = get_service(svc: 'ftp', default: 21, exit_on_fail: 1);

soc = open_sock_tcp(port);
if (!soc) exit(1, "Cannot connect to TCP port "+port+".");

if (! ftp_authenticate(socket:soc, user:login,pass:password))
{
  ftp_close(socket: soc);
  exit(1, "Could not authenticate on FTP server on port "+port+".");
}

foreach c (keys(cmd))
{
  data = 'SITE exec /bin/sh -c '+c+'\n';
  send(socket:soc, data:data);
  reply = recv_line(socket:soc, length:1024);
  txt = extract_pattern_from_resp(string: reply, pattern: cmd[c]);
  if (txt)
  {
    #set_kb_item(name:"ftp/root_via_site_exec", value:TRUE);
    if (report_verbosity <= 0)
      security_hole(port);
    else
      security_hole(port: port, extra: 
'\nThe following command :\n' +
data +
'produced :\n', txt, '\n');
    break;
  }
}

ftp_close(socket: soc);
exit(0);

