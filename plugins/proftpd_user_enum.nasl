#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(15484);
 script_version("$Revision: 1.18 $");
 script_cvs_date("$Date: 2014/05/26 15:30:09 $");

 script_cve_id ("CVE-2004-1602");
 script_bugtraq_id(11430);
 script_osvdb_id(10758);

 script_name(english:"ProFTPD Login Timing Account Name Enumeration");
 script_summary(english:"Checks the version of the remote proftpd");

 script_set_attribute(attribute:"synopsis", value:"The remote FTP server may disclose the list of valid usernames.");
 script_set_attribute(attribute:"description", value:
"The remote ProFTPd server is as old or older than 1.2.10

It is possible to determine which user names are valid on the remote
host based on timing analysis attack of the login procedure.

An attacker may use this flaw to set up a list of valid usernames for
a more efficient brute-force attack against the remote host.");
 script_set_attribute(attribute:"solution", value:"Upgrade to a newer version.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/10/15");
 script_set_attribute(attribute:"plugin_publication_date", value:"2004/10/17");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:proftpd:proftpd");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"FTP");

 script_copyright(english:"This script is Copyright (C) 2004-2014 Tenable Network Security, Inc.");

 script_dependencie("ftpserver_detect_type_nd_version.nasl", "ftp_anonymous.nasl");
 script_require_keys("ftp/proftpd", "Settings/ParanoidReport");
 script_require_ports("Services/ftp", 21);

 exit(0);
}

include("audit.inc");
include("ftp_func.inc");
include("global_settings.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_ftp_port(default: 21);

banner = get_ftp_banner(port:port);
if (! banner) exit(1);
if(egrep(pattern:"^220 ProFTPD 1\.2\.([0-9][^0-9]|10[^0-9])", string:banner))
{
  security_warning(port);
}
