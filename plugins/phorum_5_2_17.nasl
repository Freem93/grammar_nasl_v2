#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(56240);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/16 14:22:05 $");

  script_cve_id("CVE-2011-3392");
  script_bugtraq_id(49347);
  script_osvdb_id(74805);

  script_name(english:"Phorum 5.2.x < 5.2.17 'control.php' 'real_name' XSS");
  script_summary(english:"Checks Phorum Version");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web application may be affected by a cross-site scripting
vulnerability"
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-reported version number, the instance of Phorum
5.2.x hosted on the remote website is earlier than 5.2.17 and
therefore may be affected by a cross-site scripting vulnerability.

The parameter 'real_name' is not properly sanitized by the script
'control.php' before it is passed to the user.  This could be
exploited to inject arbitrary HTML or script code into a user's
browser session in the context of the affected site.

Note that Nessus did not actually test for the flaw but instead has
relied on the version in Phorum's login page."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.phorum.org/phorum5/read.php?64,149490,149490#msg-149490");
  script_set_attribute(
    attribute:"see_also",
    value:"http://holisticinfosec.org/content/view/184/45/"
  );
  script_set_attribute(attribute:"solution", value:"Update to Phorum version 5.2.17 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/08/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phorum:phorum");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("phorum_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/phorum", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

if (report_paranoia < 2)
  exit(1, "This plugin only runs if 'Report paranoia' is set to 'Paranoid'.");


port    = get_http_port(default:80, php:TRUE);
install = get_install_from_kb(appname:"phorum", port:port, exit_on_fail:TRUE);

ver = install['ver'];
dir = install['dir'];

if (ver =~ "^5(\.2)?$") exit(1, "The Phorum version ("+ver+") installed at "+build_url(port:port, qs:dir+'/')+" is not granular enough to make a determination.");

if (ver =~ "^5\.2\.([0-9]|1[0-6])($|[^0-9])")
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + build_url(port:port, qs:dir) +
      '\n  Installed version : ' + ver+
      '\n  Fixed version     : 5.2.17\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else exit(0, "The Phorum " + ver + " install at " + build_url(port:port, qs:dir+'/') + " is not affected.");
