#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(67127);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/09/12 23:24:20 $");

  script_cve_id("CVE-2013-1915");
  script_bugtraq_id(58810);
  script_osvdb_id(91948);

  script_name(english:"ModSecurity < 2.7.3 XML External Entity (XXE) Data Parsing Arbitrary File Disclosure");
  script_summary(english:"Checks version in Server response header");

  script_set_attribute(attribute:"synopsis", value:
"The remote web application firewall may be affected by a file
disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of ModSecurity installed on the
remote host is earlier than 2.7.3. It is, therefore, potentially
affected by a file disclosure vulnerability. An improperly configured
XML parser could allow untrusted XML entities from external sources to
be accepted, thus leading to possible arbitrary file disclosure.

It could also be possible for internal network servers to receive
unauthorized requests. Denial of service conditions are also possible.

Note that Nessus has not tested for this issue but has instead relied
only on the version in the server's banner.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/oss-sec/2013/q2/5");
  script_set_attribute(attribute:"see_also", value:"https://github.com/SpiderLabs/ModSecurity/blob/master/CHANGES");
  # https://github.com/SpiderLabs/ModSecurity/commit/d4d80b38aa85eccb26e3c61b04d16e8ca5de76fe");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?13229997");
  script_set_attribute(attribute:"solution", value:"Upgrade to ModSecurity version 2.7.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:modsecurity:modsecurity");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

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

fixed_ver = '2.7.3';
if (
  version =~ "^[01]\." ||
  version =~ "^2\.([0-6]|7\.[0-2])($|[^0-9])"
)
{
  if (report_verbosity > 0)
  {
    source = get_kb_item_or_exit('www/modsecurity/'+port+'/source', exit_code:1);
    report =
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_ver + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "ModSecurity", port, version);
