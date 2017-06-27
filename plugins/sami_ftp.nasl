#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(12061);
 script_version("$Revision: 1.21 $");
 script_cvs_date("$Date: 2016/11/02 14:37:09 $");

 script_cve_id("CVE-2004-2081", "CVE-2004-2082");
 script_bugtraq_id(9657);
 script_osvdb_id(3961, 45192);

 script_name(english:"Sami FTP Server Multiple DoS");
 script_summary(english:"SAMI Remote DoS");

 script_set_attribute(attribute:"synopsis", value:"The remote FTP server is prone to multiple denial of service attacks.");
 script_set_attribute(attribute:"description", value:
"The remote host is running SAMI FTP server.

There is a bug in the way this server handles certain FTP command
requests that may allow an attacker to crash the affected service.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2004/Feb/381");
 script_set_attribute(attribute:"solution", value:"Unknown at this time.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/02/16");
 script_set_attribute(attribute:"plugin_publication_date", value:"2004/02/17");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"FTP");

 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");

 script_dependencie("ftpserver_detect_type_nd_version.nasl", "ftp_anonymous.nasl");
 script_require_keys("Settings/ParanoidReport");
 script_require_ports("Services/ftp", 21);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("ftp_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_ftp_port(default: 21);

banner = get_ftp_banner(port:port);
if ( ! banner ) exit(1);

# ok, so here's what it looks like:
#220-Sami FTP Server
#220-
#220 Features p a .
#User (f00dikator:(none)): anonymous
#230 Access allowed.
#ftp> cd ~
#Connection closed by remote host.

if( "Sami FTP Server" >< banner ) {
    if (safe_checks() == 0) {
        req1 = 'USER anonymous\r\n';
        req2 = 'CWD ~\r\n';
        # SAMI ftp, when anonymous enabled, requires no password....
        soc = open_sock_tcp(port);
 	if ( ! soc ) exit(1);
        send(socket:soc, data:req1);
        r = ftp_recv_line(socket:soc);
        if ( "Access allowed" >< r ) {
            send(socket:soc, data:req2 );
            r = recv_line(socket:soc, length:64, timeout:3);
	    close(soc);
            if (!r) security_warning(port);
        }
    } else {
        security_warning(port);
    }
}
