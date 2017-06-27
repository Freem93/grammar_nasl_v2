#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10087);
 script_version ("$Revision: 1.29 $");
 script_cve_id("CVE-1999-0201");
 script_osvdb_id(75, 45712);
 script_xref(name:"Secunia", value:"30360");
 script_name(english:"Multiple FTP Server QUOTE CWD Command Home Path Disclosure");
 script_summary(english:"Get the real path of the remote ftp home");

 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by an information disclosure
vulnerability." );
 script_set_attribute(attribute:"description", value:
"It is possible to determine the full path of the home directory of
the 'ftp' user by issuing the 'CWD' command. An attacker can exploit
this to determine where to put a .rhost file using other security
flaws." );
 script_set_attribute(attribute:"see_also", value:"http://aix.software.ibm.com/aix/efixes/security/ftpd_advisory.asc" );
 script_set_attribute(attribute:"solution", value:
"Apply the latest patches from your vendor." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
 

 script_set_attribute(attribute:"plugin_publication_date", value: "1999/06/22");
 script_set_attribute(attribute:"vuln_publication_date", value: "1995/01/01");
 script_cvs_date("$Date: 2013/01/25 01:19:08 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 1999-2013 Tenable Network Security, Inc.");
 script_family(english:"FTP");
 script_dependencie("ftpserver_detect_type_nd_version.nasl", "ftp_anonymous.nasl");
 script_require_keys("ftp/anonymous");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here
#
include('global_settings.inc');
include('misc_func.inc');
include('ftp_func.inc');

port = get_ftp_port(default: 21);

anon = get_kb_item_or_exit("ftp/anonymous");

soc = open_sock_tcp(port);
if ( ! soc ) exit(1, "Cannot connect to TCP port "+port+".");

if (! ftp_authenticate(socket:soc, user:"anonymous",pass:"nessus@"))
  exit(1, "Cannot authenticate on port "+port+".");

data = 'CWD\r\n';
  send(socket:soc, data:data);
  a = recv_line(socket:soc, length:1024);
  if("550 /" >< a){
  report = string(
    "We determined that the root of the remote FTP server is located\n",
    "under ", ereg_replace(pattern:"^550 (/.*):.*", string:a, replace:"\1"),
    "\n"
  );
	
  security_warning(port:port, extra:report);
  }

ftp_close(socket: soc);

