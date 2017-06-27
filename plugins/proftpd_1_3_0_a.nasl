#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(27055);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2016/11/02 14:37:08 $");

  script_cve_id("CVE-2006-5815", "CVE-2006-6170", "CVE-2006-6171");
  script_bugtraq_id(20992);
  script_osvdb_id(30267, 30660, 30719);

  script_name(english:"ProFTPD < 1.3.0a Multiple Vulnerabilities");
  script_summary(english:"Checks version number in FTP banner");

  script_set_attribute(attribute:"synopsis", value:"The remote FTP server is affected by several vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is using ProFTPD, a free FTP server for Unix and
Linux.

According to its banner, the version of ProFTPD installed on the
remote host is earlier than 1.3.0a. As such, it may be affected by one
or more of the following vulnerabilities :

  - An off-by-one string manipulation flaw exists in the
    'sreplace' function.  (CVE-2006-5815)

  - A buffer overflow exists in the 'tls_x509_name_oneline'
    function of the mod_tls module involving the data
    length argument. (CVE-2006-6170)

  - An off-by-two buffer overflow exists due to a failure
    to properly set the buffer size limit when
    'CommandBufferSize' is specified in the configuration
    file, an issue which is disputed by the developers.
    (CVE-2006-6171)

An attacker may be able to leverage this issue to crash the affected
service or execute arbitrary code remotely, subject to the privileges
under which the application operates.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2006/Nov/315");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/452760/30/0/threaded");
  script_set_attribute(attribute:"solution", value:"Upgrade to ProFTPD version 1.3.0a or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'ProFTPD 1.2 - 1.3.0 sreplace Buffer Overflow (Linux)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/15");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:proftpd:proftpd");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_keys("ftp/proftpd", "Settings/ParanoidReport");
  script_require_ports("Services/ftp", 21);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("ftp_func.inc");


if (report_paranoia < 2) audit(AUDIT_PARANOID);


port = get_ftp_port(default: 21);

# Check the version number in the banner.
banner = get_ftp_banner(port:port);
if (banner && "ProFTPD " >< banner)
{
  # Grab the version.
  ver = NULL;

  pat = "^[0-9]{3}[ -]ProFTPD ([0-9][^ ]+) Server";
  matches = egrep(pattern:pat, string:banner);
  foreach match (split(matches))
  {
    match = chomp(match);
    item = eregmatch(pattern:pat, string:match);
    if (!isnull(item))
    {
      ver = item[1];
      break;
    }
  }

  if (ver && ver =~ "^(0\.|1\.([0-2]\.|3\.0($|rc)))")
  {
    report = strcat('\nThe banner reports this is ProFTPD version ', ver, '.\n' );
    security_hole(port:port, extra:report);
  }
}
