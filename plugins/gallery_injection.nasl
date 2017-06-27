#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID and CVE
#
# This check covers CVE-2001-1234, but a similar flaw (with a different
# CVE) was found later on.
#
# Ref: http://gallery.menalto.com/modules.php?op=modload&name=News&file=article&sid=50

include("compat.inc");

if (description)
{
  script_id(11115);
  script_version("$Revision: 1.26 $");
  script_cvs_date("$Date: 2016/10/10 15:57:05 $");

  script_cve_id("CVE-2001-1234");
  script_bugtraq_id(3397);
  script_osvdb_id(1967);

  script_name(english:"Gallery includedir Parameter Remote File Inclusion");
  script_summary(english:"Checks for the presence of includes/needinit.php");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server contains a PHP script that is prone to a remote
file inclusion vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Gallery installed on the remote host is affected by a
remote file inclusion vulnerability due to the application failing to
properly sanitize user-supplied input to the 'includedir' parameter.  An
attacker may use this flaw to inject arbitrary code in the remote host
and gain a shell with the privileges of the web server user."
  );
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2001/Oct/12");
  script_set_attribute(attribute:"solution", value:"Upgrade to Gallery 1.2.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2001/10/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2002/08/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:gallery_project:gallery");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2002-2016 Tenable Network Security, Inc.");

  script_dependencie("gallery_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/gallery", "www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

#
# The script code starts here
#

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);

install = get_install_from_kb(
  appname      : "gallery",
  port         : port,
  exit_on_fail : TRUE
);

dir = install["dir"];

w = http_send_recv3(
  item   : dir + "/errors/needinit.php?GALLERY_BASEDIR=http://xxxxxxxx/",
  method : "GET",
  port   : port,
  exit_on_fail : TRUE
);

r = strcat(w[0], w[1], '\r\n', w[2]);

if ("http://xxxxxxxx/errors/configure_instructions" >< r) security_hole(port);
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "Gallery", build_url(qs:dir, port:port));
