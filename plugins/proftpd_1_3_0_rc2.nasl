#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(19302);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2017/04/25 20:29:05 $");

  script_cve_id("CVE-2005-2390");
  script_bugtraq_id(14380, 14381);
  script_osvdb_id(18270, 18271);

  script_name(english:"ProFTPD < 1.3.0rc2 Multiple Remote Format Strings");
  script_summary(english:"Checks for multiple vulnerabilities in ProFTPD < 1.3.0rc2");

  script_set_attribute(attribute:"synopsis", value:"The remote FTP server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is using ProFTPD, a free FTP server for Unix and
Linux.

According to its banner, the version of ProFTPD installed on the
remote host suffers from multiple format string vulnerabilities, one
involving the 'ftpshut' utility and the other in mod_sql's
'SQLShowInfo' directive. Exploitation of either requires involvement
on the part of a site administrator and can lead to information
disclosure, denial of service, and even a compromise of the affected
system.");
  # https://web.archive.org/web/20090406044229/http://www.proftpd.org/docs/RELEASE_NOTES-1.3.0rc2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8be30227");
  script_set_attribute(attribute:"solution", value:"Upgrade to ProFTPD version 1.3.0rc2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/07/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/27");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:proftpd:proftpd");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2005-2017 Tenable Network Security, Inc.");

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


# Check the version number in the banner.
banner = get_ftp_banner(port:port);
if (! banner) exit(1, "No FTP banner on port "+port+".");
if (
  banner =~ "220[ -]ProFTPD (0\..+|1\.([0-2]\..+|3\.0rc1)) Server"
) security_warning(port);
