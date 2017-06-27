#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17718);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/05/26 15:30:09 $");

  script_cve_id("CVE-2006-6563");
  script_bugtraq_id(21587);
  script_osvdb_id(31509);
  script_xref(name:"EDB-ID", value:"394");
  script_xref(name:"EDB-ID", value:"3330");
  script_xref(name:"EDB-ID", value:"3333");

  script_name(english:"ProFTPD < 1.3.1rc1 mod_ctrls Module pr_ctrls_recv_request Function Local Overflow");
  script_summary(english:"Checks version of ProFTPD.");

  script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by a local buffer overflow
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is using ProFTPD, a free FTP server for Unix and
Linux.

According to its banner, the version of ProFTPD installed on the
remote host is earlier than 1.3.1rc1 and is affected by a local,
stack-based buffer overflow. The function 'pr_ctrls_recv_request' in
the file 'src/ctrls.c' belonging to the 'mod_ctrls' module does not
properly handle large values in the 'reqarglen' parameter.

This error can allow a local attacker to execute arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/archive/1/454320/100/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://sourceforge.net/mailarchive/message.php?msg_id=168826");
  script_set_attribute(attribute:"solution", value:"Upgrade to ProFTPD version 1.3.1rc1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/12/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/18");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:proftpd:proftpd");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");

  script_dependencies("ftp_overflow.nasl", "ftpserver_detect_type_nd_version.nasl");
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
if (!banner) exit(1, "Unable to obtain the banner from the FTP server listening on port "+port+".");
if ("ProFTPD" >!< banner) exit(1, "The FTP server listening on port "+port+" does not appear to be ProFTPD.");

matches = eregmatch(string:banner, pattern:"ProFTPD ([0-9a-z.]+) ");
if (isnull(matches)) exit(1, "Failed to extract the version of ProFTPD listening on port "+port+".");
version = matches[1];

if (version =~ '^1(\\.3)?$') exit(1, "The banner from ProFTPD listening on port "+port+" - "+banner+" - is not granular enough.");

if (
  version =~ "^0($|\.)" ||
  version =~ "^1\.[0-2]($|\.)" ||
  version =~ "^1\.3\.0($|\.|[^0-9])"
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + chomp(banner) +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 1.3.1rc1\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else exit(0, "The ProFTPD "+version+" server listening on port "+port+" is not affected.");
