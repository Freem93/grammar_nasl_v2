#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(73376);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/09/24 20:59:28 $");

  script_cve_id("CVE-2013-4614");
  script_bugtraq_id(60601, 66527);
  script_osvdb_id(94417, 105130);

  script_name(english:"Canon PIXMA Printer WLAN Credential Disclosure");
  script_summary(english:"Attempts to obtain WLAN credentials from printer");

  script_set_attribute(attribute:"synopsis", value:"The remote printer discloses sensitive authentication information.");
  script_set_attribute(attribute:"description", value:
"The remote printer contains a flaw that could allow a remote attacker
to obtain sensitive information. The HTTP admin interface contains
WLAN authentication information (WEP/WPA/WPA2) in plaintext.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2013/Jun/145");
  script_set_attribute(attribute:"see_also", value:"http://www.mattandreko.com/2013/06/canon-y-u-no-security.html");
  script_set_attribute(attribute:"solution", value:"Set an administrative password on the device.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2013/06/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:canon:pixma_printer");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("canon_pixma_printer_www_detect.nbin");
  script_require_ports("Services/www", 80);
  script_require_keys("www/canon_pixma");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("network_func.inc");

# May fork
port = get_kb_item_or_exit("www/canon_pixma");

# Do not pull this information across public networks
if (!is_private_addr() && !islocalnet())
  exit(0, "Remote host is not on the same local network.");

# Make the request and check for disclosure
res = http_send_recv3(
  method : "GET",
  item   : "/English/pages_WinUS/_wls_set.html",
  port   : port
);

url = "/English/pages_MacUS/_wls_set.html";

if (!res)
{
  res = http_send_recv3(
    method       : "GET",
    item         : url,
    port         : port,
    exit_on_fail : TRUE
  );
}

creds_found = make_array();
creds_source = make_array();
creds_patterns = make_array(
  # WEP inputs
  'wep_1', '<input type="password" name="WLS_TXT11".*value="([^"]+)"></td>',
  'wep_2', '<input type="password" name="WLS_TXT12".*value="([^"]+)"></td>',
  'wep_3', '<input type="password" name="WLS_TXT13".*value="([^"]+)"></td>',
  'wep_4', '<input type="password" name="WLS_TXT14".*value="([^"]+)"></td>',
  # WPA input
  'wpa', '<input type="password".*name="WLS_TXT2" value="([^"]+)"></td>',
  # WPA2 input
  'wpa2', '<input type="password".*name="WLS_TXT3" value="([^"]+)"></td>',
  # SSID
  "ssid", '<input type="hidden" name="LAN_TXT1" value="([^"]+)">'
);

foreach sought_cred (keys(creds_patterns))
{
  matches = eregmatch(pattern:creds_patterns[sought_cred] , string:res[2]);
  if (isnull(matches)) continue;

  # Source and cred
  creds_source[sought_cred] = matches[0];
  creds_found[sought_cred]  = matches[1];
}

# Build report
foreach item (keys(creds_found))
{
  if ("ssid" == item) continue; # Get SSID later
  if ("wep" >< item)  type = "WEP";
  if ("wpa" == item)  type = "WPA";
  if ("wpa2" == item) type = "WPA2";

  # Mask credential
  cred = creds_found[item];
  len = strlen(cred);
  first = substr(cred, 0, 0);
  last  = substr(cred, len - 1, len - 1);
  sanitized_cred = first + crap(data:"*", length:len - 2) + last;

  report_data +=
    '\n  Type       : ' + type +
    '\n  Credential : ' + sanitized_cred;
}

# Add SSID
matches = eregmatch(pattern:creds_patterns['ssid'] , string:res[2]);
if (!isnull(matches))
  report_data += '\n  SSID       : ' + matches[1] + '\n';

if (strlen(report_data) > 0)
{
  if (report_verbosity > 0)
  {
    report =
      '\n' + 'Nessus was able to obtain the following sensitive information' +
      '\n' + 'from the remote printer : ' +
      '\n' + 
      '\n' + '  URL        : ' + build_url(qs:url, port:port) +
      report_data +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else exit(0, "The remote Canon PIXMA printer listening on port " + port + " is not affected.");
