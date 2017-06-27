#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(24817);
  script_version("$Revision: 1.25 $");
  script_cvs_date("$Date: 2017/05/16 19:35:39 $");

  script_cve_id("CVE-2007-1473");
  script_bugtraq_id(22984);
  script_osvdb_id(33084);

  script_name(english:"Horde NLS.php Language Selection new_lang Parameter XSS");
  script_summary(english:"Checks for an XSS flaw in Horde");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is vulnerable to
a cross-site scripting attack.");
  script_set_attribute(attribute:"description", value:
"The version of Horde installed on the remote host fails to sanitize
input to the 'new_lang' parameter before using it in the
'framework/NLS/NLS.php' script to generate dynamic content.  An
unauthenticated, remote attacker may be able to leverage this issue to
inject arbitrary HTML or script code into a user's browser to be
executed within the security context of the affected site.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2007/Mar/241");
  script_set_attribute(attribute:"see_also", value:"https://lists.horde.org/archives/announce/2007/000315.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Horde version 3.1.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"plugin_publication_date", value: "2007/03/16");
  script_set_attribute(attribute:"vuln_publication_date", value: "2007/03/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:horde:horde_application_framework");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2007-2017 Tenable Network Security, Inc.");

  script_dependencies("horde_detect.nasl", "imp_detect.nasl", "cross_site_scripting.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:80, php: 1, no_xss: 1);

xss = string("alert('", SCRIPT_NAME, "');");
exploit = string('"><body onload="', xss);


# Test possible installs.
installs = make_list();
imp = get_kb_item(string("www/", port, "/imp"));
if (imp) installs = make_list(installs, imp);
horde = get_kb_item(string("www/", port, "/horde"));
if (horde)
{
  installs = make_list(installs, horde);
  if (thorough_tests)
  {
    matches = eregmatch(string:horde, pattern:"^(.+) under (/.*)$");
    if (!isnull(matches))
    {
      horde_dir = matches[2];
      apps = make_list(
        "chora",
        "dimp",
        "gollem",
        # "imp",
        "ingo",
        "kronolith",
        "mimp",
        "mnemo",
        "nag",
        "sork",
        "trean",
        "turba",
        "whups"
      );
      foreach app (apps)
        installs = make_list(installs, string("unknown under ", horde_dir, "/", app));
    }
  }
}
foreach install (installs)
{
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches))
  {
    dir = matches[2];

    # Send a request to exploit the flaw.
    r = http_send_recv3(method:"GET", 
      item:string(
        dir, "/login.php?",
        "new_lang=", urlencode(str:exploit)
      ), 
      port:port,
      exit_on_fail: 1
    );
    res = r[2];

    # There's a problem if our exploit as the language.
    exploit = str_replace(find:"_", replace:"-", string:exploit);
    if (string('<html lang="', exploit) >< res)
    {
      security_warning(port);
      set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
      exit(0);
    }
  }
}
