#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(19502);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2005-2717");
  script_bugtraq_id(14651);
  script_osvdb_id(18954);

  script_name(english:"WebCalendar send_reminders.php includedir Parameter Remote File Inclusion");
  script_summary(english:"Checks for includedir parameter remote file include vulnerability in WebCalendar");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server has a PHP script that is affected by a remote
file include vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote version of WebCalendar fails to sanitize user-supplied
input to the 'includedir' parameter of the 'send_reminders.php'
script.  By leveraging this flaw, an attacker may be able to view
arbitrary files on the remote host and execute arbitrary PHP code,
possibly taken from third-party hosts." );
 script_set_attribute(attribute:"see_also", value:"http://sourceforge.net/project/shownotes.php?release_id=350336" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to WebCalendar 1.0.1 or newer." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/08/25");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/08/24");
 script_cvs_date("$Date: 2012/12/20 19:22:43 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:webcalendar:webcalendar");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2012 Tenable Network Security, Inc.");

  script_dependencies("webcalendar_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/webcalendar"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];
  dir = matches[2];

  # Try to exploit the flaw in config.php to read /etc/passwd.
  r = http_send_recv3(method:"GET", port: port,
    item:string(
      dir, "/tools/send_reminders.php?",
      "includedir=/etc/passwd%00"
    ));
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if...
  if (
    # there's an entry for root or...
    #
    # nb: this is unlikely since the app requires magic_quotes_gpc to be
    #     enabled but still...
    egrep(string:res, pattern:"root:.*:0:[01]:") ||
    # we get an error saying "failed to open stream" or "Failed opening".
    #
    # nb: this suggests magic_quotes_gpc was enabled but passing
    #     remote URLs would probably still work.
    egrep(string:res, pattern:"Warning.+\(/etc/passwd.+failed to open stream") ||
    egrep(string:res, pattern:"Warning.+ Failed opening '/etc/passwd.+for inclusion")
  ) {
    security_hole(port);
    exit(0);
  }
  # Checking the version number is the only way to go if PHP's
  # display_errors setting is disabled.
  else if (ver =~ "^(0\.|1\.0\.0)") {
    report = string(
      "Nessus has determined the vulnerability exists on the remote\n",
      "host simply by looking at the version number of WebCalendar\n",
      "installed there.\n"
    );
    security_hole(port:port, extra:report);
    exit(0);
  }
}
