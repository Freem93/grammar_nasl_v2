#
# (C) Tenable Network Security, Inc.
#

# Date: Sat, 28 Feb 2004 21:52:33 +0000
# From: axl rose <rdxaxl@hotmail.com>
# To: full-disclosure@lists.netsys.com, bugtraq@securityfocus.com
# Cc: info@texis.com
# Subject: [Full-Disclosure] Critical WFTPD buffer overflow vulnerability


include("compat.inc");

if(description)
{
 script_id(12083);
 script_cve_id("CVE-2004-0340", "CVE-2004-0341", "CVE-2004-0342");
 script_bugtraq_id(9767);
 script_osvdb_id(4114, 4115, 4116, 14763, 14764, 14765);
 script_version ("$Revision: 1.22 $");
 
 script_name(english:"WFTP 3.21 Multiple Vulnerabilities (OF, DoS)");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code may be run on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote FTP server is  vulnerable to at least two remote stack-based 
overflows and two Denial of Service attacks.  An attacker can use these 
flaws to gain remote access to the WFTPD server." );
 script_set_attribute(attribute:"solution", value:
"If you are using wftp, then upgrade to a version greater than 3.21 R1, 
if you are not, then contact your vendor for a fix." );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/02/29");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/02/28");
 script_cvs_date("$Date: 2016/05/04 18:02:23 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english: "WFTPD 3.21 remote overflows");
 script_category(ACT_MIXED_ATTACK);  
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 script_family(english:"FTP");
 script_dependencie("ftpserver_detect_type_nd_version.nasl","ftp_anonymous.nasl");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

# The script code starts here
#
include("global_settings.inc");
include("ftp_func.inc");

port = get_ftp_port(default: 21);

banner = get_ftp_banner(port: port);
if ( "WFTPD" >!< banner ) exit(0, "The remote FTP server on port "+port+" is not WFTPD.");

if(safe_checks()) {
 if (egrep(string:banner, pattern:"^220.*WFTPD ([0-2]\..*|3\.[0-2]) service")) {
 txt = "
Nessus reports this vulnerability using only information that was 
gathered. Use caution when testing without safe checks enabled.";
 security_hole(port:port, extra: txt);
 }
 exit(0);
} else if (report_paranoia == 2) {
 login = get_kb_item("ftp/login");
 pass  = get_kb_item("ftp/password");
 soc = open_sock_tcp(port);
 if(! soc) exit(1, "TCP connection failed to port "+port+".");
    if(login) {
        if(ftp_authenticate(socket:soc, user:login, pass:pass)) {
            send(socket:soc, data:string("LIST -",crap(500)," \r\n"));
            ftp_close(socket:soc);
            soc2 = open_sock_tcp(port);
            if (!soc2) security_hole(port);
            r = ftp_recv_line(socket:soc2);        
            if (!r) security_hole(port);
        }
    }
}
