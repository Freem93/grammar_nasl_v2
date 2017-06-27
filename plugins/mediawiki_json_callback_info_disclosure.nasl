#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31346);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/05/09 15:44:47 $");

  script_cve_id("CVE-2008-1318");
  script_bugtraq_id(28070);
  script_osvdb_id(42588);
  script_xref(name:"Secunia", value:"29216");

  script_name(english:"MediaWiki JSON Callback Crafted API Request Information Disclosure");
  script_summary(english:"Requests an edittoken with a JSON callback.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of MediaWiki installed on the remote host is affected by
an information disclosure vulnerability. A remote attacker can exploit
this via the 'callback' parameter in an API call for JavaScript Object
Notation (JSON) formatted results.");
   # http://lists.wikimedia.org/pipermail/mediawiki-announce/2008-March/000070.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?83a05f7b");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MediaWiki 1.11.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(200);

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/03/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:mediawiki:mediawiki");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("mediawiki_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("installed_sw/MediaWiki", "www/PHP");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "MediaWiki";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);
dir = install['path'];
install_url = build_url(qs:dir, port:port);

# Request an edittoken.
callback = "nessus" + unixtime();
url = "/api.php?action=query&prop=info&intoken=edit&titles=Main_Page&format=json&callback=" + callback;

w = http_send_recv3(
  method : "GET",
  item   : dir + url, 
  port   : port,
  exit_on_fail : TRUE
);
res = w[2];

# There's a problem if...
if (
  # our callback function was returned and...
  (callback + '({"error":' >< res) &&
  # we see an error saying the edit is not allowed
  "Action 'edit' is not allowed for the current user" >< res
)
{
  output = strstr(res, (callback + '({"error":'));
  if (empty_or_null(output)) output = res;

  security_report_v4(
    port        : port,
    severity    : SECURITY_WARNING,
    generic     : TRUE,
    request     : make_list(install_url + url),
    output      : chomp(res)
  );
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
