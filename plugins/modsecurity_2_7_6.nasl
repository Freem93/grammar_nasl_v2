#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73962);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/09/12 18:55:23 $");

  script_cve_id("CVE-2013-5705");
  script_bugtraq_id(66552);
  script_osvdb_id(105191);

  script_name(english:"ModSecurity < 2.7.6 Chunked Header Filter Bypass");
  script_summary(english:"Checks version in Server response header");

  script_set_attribute(attribute:"synopsis", value:
"The remote web application firewall may be affected by a filter bypass
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of ModSecurity installed on the
remote host is prior to 2.7.6. It is, therefore, potentially affected
by a filter bypass vulnerability.

A filter bypass vulnerability exists with 'modsecurity.c' not properly
handling chunked requests. A remote attacker, with a specially crafted
request, can bypass security filters and inject arbitrary content.

Note that Nessus has not tested for this issue but has instead relied
only on the version in the server's banner.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/SpiderLabs/ModSecurity/releases/tag/v2.7.6");
  script_set_attribute(attribute:"see_also", value:"http://martin.swende.se/blog/HTTPChunked.html");
  # https://github.com/SpiderLabs/ModSecurity/commit/f8d441cd25172fdfe5b613442fedfc0da3cc333d
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?88e6187f");
  script_set_attribute(attribute:"solution", value:"Upgrade to ModSecurity version 2.7.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:modsecurity:modsecurity");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("modsecurity_http_version.nasl");
  script_require_keys("www/ModSecurity", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

# Make sure this is ModSecurity
get_kb_item_or_exit('www/'+port+'/modsecurity');
version = get_kb_item_or_exit('www/modsecurity/'+port+'/version', exit_code:1);
backported = get_kb_item_or_exit('www/modsecurity/'+port+'/backported', exit_code:1);

if (report_paranoia < 2 && backported) audit(AUDIT_BACKPORT_SERVICE, port, "ModSecurity");

if (version == 'unknown') audit(AUDIT_UNKNOWN_WEB_SERVER_VER, "ModSecurity", port);

fixed_ver = '2.7.6';
if (
  version =~ "^[01]\." ||
  version =~ "^2\.([0-6]|7\.[0-5])($|[^0-9])"
)
{
  if (report_verbosity > 0)
  {
    source = get_kb_item_or_exit('www/modsecurity/'+port+'/source', exit_code:1);

    report =
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_ver + '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "ModSecurity", port, version);
