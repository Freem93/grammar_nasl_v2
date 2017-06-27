#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17272);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2016/11/03 14:16:36 $");

  script_cve_id("CVE-2005-0658");
  script_bugtraq_id(12721);
  script_osvdb_id(14362);

  script_name(english:"TYPO3 'cmw_linklist Extension' 'category_uid' Parameter SQL Injection");
  script_summary(english:"Detects SQL injection vulnerability in the TYPO3 CMW Linklist extension.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a SQL
injection attack.");
  script_set_attribute(attribute:"description", value:
"The installation of TYPO3 on the remote host is vulnerable to remote
SQL injection attacks through the parameter 'category_uid' used by the
third-party cmw_linklist extension. By exploiting this flaw, a remote
attacker can uncover sensitive information or even modify existing
data.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/Mar/79");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/Mar/89");
  # http://typo3.org/teams/security/security-bulletins/typo3-extensions/typo3-20050304-1/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dd04678a");
  script_set_attribute(attribute:"solution", value:"Upgrade to cmw_linklist extension version 1.5.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/03/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/03/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:typo3:typo3");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

  script_dependencies("typo3_detect.nasl", "no404.nasl");
  script_require_keys("installed_sw/TYPO3", "www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "TYPO3";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

if (get_kb_item("www/no404/" + port)) exit(1, "The web server on port "+port+" does not support 404 error codes.");

install = get_single_install(
  app_name : app,
  port     : port
);
dir = install['path'];
install_url = build_url(qs:dir, port:port);

# Check if the extension is available.
#
# nb: the flaw is in pi1/class.tx_cmwlinklist_pi1.php so check for that.
w = http_send_recv3(
  method : "GET",
  item   : dir + "/typo3conf/ext/cmw_linklist/pi1/class.tx_cmwlinklist_pi1.php",
  port   : port,
  exit_on_fail : TRUE
);

# If it is...
if (w[0] =~ "^HTTP/.+ 200 OK")
{
  # Grab the main page.
  w = http_send_recv3(method:"GET", item:dir + "/index.php", port:port, exit_on_fail:TRUE);
  res = w[2];

  # Find the Links page.
  #
  # nb: the actual text could be in the native language or even
  #     set by the administrator making it hard to get a
  #     robust pattern. :-(
  pat = '<a href="([^"]+)".+(Links</a>|name="links")';
  matches = egrep(pattern:pat, string:res, icase:TRUE);
  foreach match (split(matches))
  {
    match = chomp(match);
    links = eregmatch(pattern:pat, string:match);
    if (!empty_or_null(links[1]))
    {
      links = links[1];
      if (links !~ "^/") links = "/" + links;
      break;
    }
  }

  # Find a single link in the Links page (which should be local).
  if (!empty_or_null(links) && links !~ "^http")
  {
    w = http_send_recv3(method:"GET", item:string(dir, links), port:port, exit_on_fail:TRUE);
    res = w[2];

    pat = '<A HREF="([^"]+&action=getviewcategory[^"]*">';
    matches = egrep(pattern:pat, string:res, icase:TRUE);
    foreach match (split(matches))
    {
      match = chomp(match);
      link = eregmatch(pattern:pat, string:match);
      if (!empty_or_null(link[1]))
      {
        link = link[1];
        break;
      }
    }

    # Try to exploit vulnerability by issuing an impossible request.
    #
    # nb: The fix for the vulnerability evaluates category_uid as an
    #     integer; thus, it's vulnerable if the result fails to
    #     return any links.
    if (link)
    {
      exploit = ereg_replace(
        string:link,
        pattern:"&category_uid=([0-9]+)",
        # cause query to fail by tacking " and 1=0 " onto the category_uid.
        replace:"\1%20and%201=0%20"
      );
      w = http_send_recv3(method:"GET", item:exploit, port:port, exit_on_fail:TRUE);
      res = w[2];

      # If there aren't any links, there's a problem.
      if (res !~ "&action=getviewclickedlink&uid=")
      {
        set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);
        security_hole(port);
        exit(0);
      }
    }
  }
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
