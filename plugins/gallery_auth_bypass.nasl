#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(12278);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2013/04/02 13:59:06 $");

  script_cve_id("CVE-2004-0522");
  script_bugtraq_id(10451);
  script_osvdb_id(6524);

  script_name(english:"Gallery init.php Authentication Bypass");
  script_summary(english:"Attempts to bypass authentication in Gallery");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host is running a PHP application that is affected by an
authentication bypass vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Gallery hosted on the remote web server is affected by
an authentication bypass issue.  A flaw exists that may allow an
attacker to bypass the authentication mechanism of this software by
making requests including the options 'GALLERY_EMBEDDED_INSIDE' and
'GALLERY_EMBEDDED_INSIDE_TYPE'.  An attacker who can bypass
authentication will obtain Gallery administrator privileges."
  );
  script_set_attribute(attribute:"see_also", value:"http://galleryproject.org/node/123");
  script_set_attribute(attribute:"solution", value:"Upgrade to Gallery 1.4.3-pl2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/06/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2004/06/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/06/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:gallery_project:gallery");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");

  script_dependencies("gallery_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/gallery", "www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

#
# The script code starts here


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);

install = get_install_from_kb(
  appname:"gallery",
  port:port,
  exit_on_fail:TRUE
);

dir = install["dir"];

r = http_send_recv3(
  method : "GET",
  item   : dir + "/index.php",
  port   : port,
  exit_on_fail : TRUE
);

if (egrep(pattern:'<span class="admin"><a id="popuplink_1".*\\[login\\]', string:r[2]))
{
  r = http_send_recv3(
    method : "GET",
    item   : dir + "/index.php?GALLERY_EMBEDDED_INSIDE=y",
    port   : port,
    exit_on_fail : TRUE
  );

  if (!egrep(pattern:'<span class="admin"><a id="popuplink_1".*\\[login\\]', string:r[2]))
  {
    security_hole(port);
    exit(0);
  }
}

audit(AUDIT_WEB_APP_NOT_AFFECTED, "Gallery", build_url(qs:dir,port:port));
