#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73640);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/20 14:02:59 $");

  script_cve_id("CVE-2014-0160");
  script_bugtraq_id(66690);
  script_osvdb_id(105465);
  script_xref(name:"CERT", value:"720951");
  script_xref(name:"EDB-ID", value:"32745");
  script_xref(name:"EDB-ID", value:"32764");
  script_xref(name:"EDB-ID", value:"32791");
  script_xref(name:"EDB-ID", value:"32998");

  script_name(english:"FileZilla Server < 0.9.44 OpenSSL Heartbeat Information Disclosure (Heartbleed)");
  script_summary(english:"Checks the banner version of FileZilla Server");

  script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by an information disclosure vulnerability.");
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of FileZilla Server running on
the remote host is prior to 0.9.44. It is, therefore, affected by
an information disclosure vulnerability.

An information disclosure flaw exists with the OpenSSL included with
FileZilla Server. A remote attacker could read the contents of up to
64KB of server memory, potentially exposing passwords, private keys,
and other sensitive data.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");

  script_set_attribute(attribute:"see_also", value:"https://filezilla-project.org/");
  script_set_attribute(attribute:"see_also", value:"http://www.heartbleed.com");
  script_set_attribute(attribute:"see_also", value:"https://eprint.iacr.org/2014/140");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/vulnerabilities.html#2014-0160");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20140407.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to FileZilla Server version 0.9.44 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  
  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:filezilla:filezilla_server");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_require_keys("ftp/filezilla");
  exit(0);
}

include("audit.inc");
include("ftp_func.inc");
include("global_settings.inc");
include("misc_func.inc");

exit(0, "Temporarily deprecated.");

port = get_ftp_port(default: 21);

banner = get_ftp_banner(port:port);
if (!banner) audit(AUDIT_WEB_BANNER_NOT, port);
if ("FileZilla Server" >!< banner) audit(AUDIT_WRONG_WEB_SERVER, port, "FileZilla Server");

banner = strstr(banner, "FileZilla Server");
banner = banner - strstr(banner, '\r\n');

version = eregmatch(pattern:"FileZilla Server version (\d\.\d\.(\d\d[a-e]|\d\d|\d[a-e]|\d))",string:banner);

if(isnull(version)) audit(AUDIT_UNKNOWN_WEB_SERVER_VER, "FileZilla Server", port);

if (
  version[1] =~ "^0\.[0-8]($|[^0-9])" ||
  version[1] =~ "^0\.9\.([0-9]|[1-3][0-9]|4[0-3])($|[^0-9])"
)
{
  if(report_verbosity > 0)
  {
    report =
      '\n  Application : FileZilla Server' +
      '\n  Version    : ' + version[1] +
      '\n  Fixed      : 0.9.44' +
      '\n  Banner     : ' + banner +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_INST_VER_NOT_VULN, "FileZilla Server", version[1]);
