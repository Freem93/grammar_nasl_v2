#
# This script was written by H D Moore
#

include("compat.inc");

if(description)
{
  script_id(10990);
  script_version("$Revision: 1.30 $");
  script_cvs_date("$Date: 2016/12/06 20:03:50 $");

  # script_cve_id("CVE-MAP-NOMATCH");
  script_osvdb_id(813);
  # NOTE: reviewed, and no CVE id currently assigned (jfs, december 2003)

  script_name(english:"Multiple Vendor Embedded FTP Service Any Username Authentication Bypass");
  script_summary(english:"FTP Service allows any username.");

  script_set_attribute(attribute:"synopsis", value:
"A random username and password can be used to authenticate to the
remote FTP server.");
  script_set_attribute(attribute:"description", value:
"The FTP server running on the remote host can be accessed using a
random username and password. Nessus has enabled some countermeasures
to prevent other plugins from reporting vulnerabilities incorrectly
because of this.");
  script_set_attribute(attribute:"solution", value:
"Correct the FTP server's configuration so that the service handles
authentication requests properly.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");


  script_set_attribute(attribute:"plugin_publication_date", value:"2002/06/05");
  script_set_attribute(attribute:"vuln_publication_date", value: "2002/01/01");
  
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2002-2016 Digital Defense Inc.");

  script_family(english: "FTP");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/ftp", 21);
  exit(0);
}

#
# The script code starts here
#
include('audit.inc');
include('global_settings.inc');
include('ftp_func.inc');
include('misc_func.inc');

port = get_ftp_port(default: 21);
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

n_cnx = 0; n_log = 0;

banner = get_ftp_banner(port:port);
if ( ! banner ) audit(AUDIT_NO_BANNER, port);

for (i = 0; i < 4; i ++)
{
 soc = open_sock_tcp(port);
 if(soc)
 {
   n_cnx ++;
   u = rand_str(); p = rand_str();
   if (ftp_authenticate(socket:soc, user: u, pass: p))
   {
     debug_print("ftp_authenticate(user: ", u, ", pass: ", p, ") = OK\n");
     n_log ++;
   }
   ftp_close(socket: soc);
 }
 else
  sleep(1);

 debug_print('n_log=', n_log, '/ n_cnx=', n_cnx, '\n');
 if (n_cnx > 0 && n_log > 0 ) # >= n_cnx ?
 {
  set_kb_item(name:"ftp/" + port + "/AnyUser", value:TRUE);
  # if (report_verbosity > 1)
   security_warning(port:port);
  exit(0);
 }
}

audit(AUDIT_LISTEN_NOT_VULN, 'FTP Server', port);
