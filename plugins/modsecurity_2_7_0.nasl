#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(67126);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/11/18 19:03:16 $");

  script_cve_id("CVE-2012-4528");
  script_bugtraq_id(56096);
  script_osvdb_id(86408);

  script_name(english:"ModSecurity < 2.7.0 Multipart Request Parsing Filter Bypass");
  script_summary(english:"Checks version in Server response header");

  script_set_attribute(attribute:"synopsis", value:
"The remote web application firewall may be affected by a security
bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of ModSecurity installed on the
remote host is earlier than 2.7.0. It is, therefore, potentially
affected by a security bypass vulnerability. An error exists related
to HTTP POST requests and 'Content-Disposition' headers containing
extra lines that could allow a remote attacker to bypass certain
filters and carry out attacks.

Note that Nessus has not tested for this issue but has instead relied
only on the version in the server's banner.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2012/Oct/113");
  script_set_attribute(attribute:"see_also", value:"https://github.com/SpiderLabs/ModSecurity/blob/master/CHANGES");
  script_set_attribute(attribute:"solution", value:"Upgrade to ModSecurity version 2.7.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:modsecurity:modsecurity");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

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

fixed_ver = '2.7.0';
if (
  version =~ "^[01]\." ||
  version =~ "^2\.[0-6]($|[^0-9])"
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
