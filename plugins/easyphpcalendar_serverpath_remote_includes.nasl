#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(18617);
  script_version("$Revision: 1.13 $");

  script_cve_id("CVE-2005-2155");
  script_bugtraq_id(14131);
  script_osvdb_id(17723, 17731, 17732, 17733, 17734);

  script_name(english:"EasyPHPCalendar Multiple Script serverPath Parameter Remote File Inclusion");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is susceptible
to remote file inclusion attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host is running EasyPHPCalendar, a web-based calendar
system written in PHP. 

The installed version of EasyPHPCalendar allows remote attackers to
control the 'serverPath' variable used when including PHP code in
several of the application's scripts.  Provided PHP's
'register_globals' setting is enabled, an attacker is able to view
arbitrary files on the remote host and even execute arbitrary PHP
code, possibly taken from third-party hosts." );
 script_set_attribute(attribute:"see_also", value:"http://secunia.com/advisories/15893" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to EasyPHPCalendar version 6.2.8 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/07/05");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/07/05");
 script_cvs_date("$Date: 2011/03/14 21:48:03 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  summary["english"] = "Checks for serverPath remote file include vulnerabilities in EasyPHPCalendar";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
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


# Loop through CGI directories.
foreach dir (cgi_dirs()) {
  # Try to exploit one of the flaws to read /etc/passwd.
  r = http_send_recv3(method:"GET",
    item:string(
      dir, "/calendar.php?",
      "serverPath=/etc/passwd%00" ), 
    port:port );
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if there's an entry for root.
  if (egrep(string:res, pattern:"root:.*:0:[01]:")) {
    security_warning(port);
    exit(0);
  }
}
