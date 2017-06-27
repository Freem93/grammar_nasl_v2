#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71954);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/01/23 22:03:56 $");

  script_cve_id("CVE-2013-6196");
  script_bugtraq_id(64458);
  script_osvdb_id(101274);

  script_name(english:"HP Autonomy Ultraseek 5 Unspecified XSS");
  script_summary(english:"Version check for Ultraseek 5");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host is running a version of HP Autonomy Ultraseek that is
affected by a cross-site scripting vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running HP Autonomy Ultraseek version 5.  It is,
therefore, affected by an unspecified cross-site scripting vulnerability
due to a failure to properly sanitize user-supplied input."
  );
  script_set_attribute(attribute:"see_also", value:"http://jvn.jp/en/jp/JVN69700259/index.html");
  script_set_attribute(attribute:"see_also", value:"http://jvndb.jvn.jp/en/contents/2013/JVNDB-2013-000126.html");
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c04041082
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4191789b");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2013/Dec/120");
  script_set_attribute(attribute:"solution", value:"Upgrade to Ultraseek 6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/12/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:autonomy_ultraseek");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8765);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:8765);

app_name = 'HP Autonomy Ultraseek';

server_header = http_server_header(port:port);
if (isnull(server_header)) audit(AUDIT_WEB_NO_SERVER_HEADER, port);
if ('ultraseek' >!< tolower(server_header)) audit(AUDIT_WRONG_WEB_SERVER, port, app_name);

match = eregmatch(string:server_header, pattern:'[Uu]ltraseek[/|\\s]((?:\\d+\\.)*\\d+)');
if (isnull(match)) audit(AUDIT_UNKNOWN_WEB_SERVER_VER, app_name, port);
version_discovered = match[1];

version_fixed = '6.0.0';
if (version_discovered =~ "^5\.")
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + server_header +
      '\n  Installed version : ' + version_discovered +
      '\n  Fixed version     : ' + version_fixed +
      '\n';
    security_note(port:port, extra:report);
  }
  else security_note(port);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version_discovered);
