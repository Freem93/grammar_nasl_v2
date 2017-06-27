#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22307);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2016/10/27 15:03:54 $");

  script_cve_id("CVE-2006-4624");
  script_bugtraq_id(19831, 20021);
  script_osvdb_id(28436);

  script_name(english:"Mailman Utils.py Spoofed Log Entry Injection");
  script_summary(english:"Checks if Mailman filters invalid chars from PATH_INFO");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a Python application that is affected
by a log spoofing vulnerability." );
  script_set_attribute(attribute:"description", value:
"The version of Mailman installed on the remote host fails to sanitize
user-supplied input before writing it to the application's 'error'
log.  An unauthenticated, remote attacker can leverage this flaw to
spoof log messages. 

In addition, the application reportedly is affected by a denial of
service issue involving headers that do not conform to RFC 2231 as
well as several cross-site scripting vulnerabilities." );
   # http://web.archive.org/web/20081010174947/http://moritz-naumann.com/adv/0013/mailmanmulti/0013.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?21f344c0" );
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2006/Sep/244" );
   # http://sourceforge.net/project/shownotes.php?release_id=444295&group_id=103
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bdca7587" );
   # http://mail.python.org/pipermail/mailman-announce/2006-September/000086.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e043174e" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mailman version 2.1.9 rc1 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(94);
  script_set_attribute(attribute:"plugin_publication_date", value: "2006/09/05");
  script_set_attribute(attribute:"vuln_publication_date", value: "2006/09/02");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:gnu:mailman");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");

  script_dependencies("mailman_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);


# Test an install.
install = get_kb_item(string("www/", port, "/Mailman"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Try to exploit the flaw.
  list = "mailman";
  w = http_send_recv3(method:"GET",
    item:string(dir, "/listinfo/", list, "%0a", SCRIPT_NAME), 
    port:port
  );
  if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
  res = w[2];

  # There's a problem if the listname was not sanitized properly.
  if (string('No such list <em>', list, '\n', SCRIPT_NAME, '</em>') >< res)
  {
    security_note(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
  }
}
