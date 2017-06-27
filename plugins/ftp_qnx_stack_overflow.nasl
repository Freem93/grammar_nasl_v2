#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10692);
 script_version("$Revision: 1.27 $");
 script_cvs_date("$Date: 2016/10/10 15:57:05 $");

 script_cve_id("CVE-2001-0325");
 script_bugtraq_id(2342);
 script_osvdb_id(12212);

 script_name(english:"QNX RTP FTP stat Command strtok() Function Overflow");
 script_summary(english:"strock() stack overflow");

 script_set_attribute(attribute:"synopsis", value:"The remote FTP server is affected by a stack overflow vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote FTP server is vulnerable to a stack overflow when calling
the 'strtok()' function. An attacker can exploit this flaw to execute
arbitrary code on the remote host.");
 # https://web.archive.org/web/20010319061218/http://archives.neohapsis.com/archives/bugtraq/2001-02/0031.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?20b5c285");
 script_set_attribute(attribute:"solution", value:"There is no known solution at this time.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2001/02/02");
 script_set_attribute(attribute:"plugin_publication_date", value:"2001/06/15");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_DESTRUCTIVE_ATTACK);

 script_copyright(english:"This script is Copyright (C) 2001-2016 Tenable Network Security, Inc.");
 script_family(english:"FTP");

 script_dependencie("ftpserver_detect_type_nd_version.nasl", "ftp_anonymous.nasl");
 script_require_keys("ftp/login", "Settings/ParanoidReport");
 script_require_ports("Services/ftp", 21);

 exit(0);
}

include("audit.inc");
include('global_settings.inc');
include('misc_func.inc');
include('ftp_func.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

login = get_kb_item_or_exit("ftp/login");
password = get_kb_item("ftp/password");


port = get_ftp_port(default: 21);

soc = open_sock_tcp(port);
if (! soc) exit(1, "Cannot connect to TCP port "+port+".");

if (! ftp_authenticate(socket:soc, user:login,pass:password))
{
  ftp_close(socket: soc);
  exit(1, "Cannot authenticate on on port "+port+".");
}

 crp = crap(data:"a ", length:320);
 req = strcat('STAT ', crp, '\r\n');
 send(socket:soc, data:req);
 r = recv_line(socket:soc, length:4096, timeout: 3 * get_read_timeout());
 if(!r)
 {
  security_hole(port);
  exit(0);
 }

ftp_close(socket: soc);


