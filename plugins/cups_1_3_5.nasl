#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(29727);
  script_version("$Revision: 1.26 $");
  script_cvs_date("$Date: 2016/05/04 18:02:14 $");

  script_cve_id("CVE-2007-5849");
  script_bugtraq_id(26917);
  script_osvdb_id(40719);

  script_name(english:"CUPS SNMP Back End (backend/snmp.c) asn1_get_string Function Crafted SNMP Response Remote Overflow");
  script_summary(english:"Checks the CUPS server version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote printer service is affected by a buffer overflow
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of CUPS installed on the remote
host contains a stack-based integer overflow in 'asn1_get_string' in
'backend/snmp.c'. Provided the SNMP backend is configured in CUPS
(true by default in CUPS 1.2 but not 1.3), an attacker may be able to
exploit this issue by using specially crafted SNMP responses with
negative lengths to overflow a buffer and execute arbitrary code on
the affected system.");
  script_set_attribute(attribute:"see_also", value:"http://www.cups.org/str.php?L2589");
  # http://www.cups.org/articles.php?L519 (this original link is now 404)
  # https://web.archive.org/web/20070702081556/http://www.cups.org/articles.php?L519
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?34761db3");
  script_set_attribute(attribute:"solution", value:"Upgrade to CUPS version 1.3.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189);

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/11/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/12/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/19");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:cups");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 631);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:631, embedded:TRUE);

banner = get_http_banner(port:port, exit_on_fail: 1);

# Get the version.
source = "";
version = "";

#   - try the Server response header.
server = chomp(egrep(string: banner, pattern: "^Server:"));
if (server)
{
  if ("CUPS" >!< server) audit(AUDIT_NOT_LISTEN, "CUPS", port);

  set_kb_item(name:"www/"+port+"/cups/running", value:TRUE);
  v = eregmatch(string: server, pattern: "CUPS/([0-9][^ ]*)");
  if (!isnull(v))
  {
    version = v[1];
    source = server;
  }
}

#   - look in the title if ServerTokens is 'ProductOnly', 'Major', or 'Minor'.
if (!version || ereg(pattern:"^[0-9]+(\.[0-9]+)?$", string:version))
{
  res = tolower(http_get_cache(port:port, item:'/', exit_on_fail:TRUE));

  # Check for a few strings to make sure it's CUPS if there's no Server response header.
  if (!server)
  {
    if (
      (
        '<title>home - cups' >< res ||
        '</a> cups is copyright '  >< res ||
        '</a>. cups is copyright '  >< res ||
        '<td class="trailer">cups and the cups logo are trademarks ' >< res ||
        '<small>the common unix printing sytem, cups, and the cups logo are the trademark ' >< res
      ) &&
      (
        '<link rel="shortcut icon" href="/images/cups-icon.png"' >< res ||
        '<td class="unsel"><a href="/jobs">' >< res ||
        '<a class="unsel" href="/jobs">' >< res ||
        '<a href="/admin?op=add-printer">' >< res
      )
    ) set_kb_item(name:"www/"+port+"/cups/running", value:TRUE);
    else audit(AUDIT_NOT_LISTEN, "CUPS", port);
  }

  pat = "<title>.*cups v?([0-9.rcb]+).*</title>";
  matches = egrep(pattern:pat, string:res);
  if (matches)
  {
    foreach match (split(matches, keep:FALSE))
    {
      item = eregmatch(pattern:pat, string:match);
      if (!isnull(item))
      {
        version = item[1];
        source = match;
        break;
      }
    }
  }
}
if (!version) audit(AUDIT_UNKNOWN_WEB_SERVER_VER, "CUPS", port);

set_kb_item(name:"www/cups", value:TRUE);
set_kb_item(name:"cups/"+port+"/version", value:version);
set_kb_item(name:"cups/"+port+"/source", value:source);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# nb: STR #2589 says 1.1 is not affected.
if (
  version =~ "^1\.(2|3\.[0-4])($|[^0-9])" ||
  version =~ "^1\.3(rc|b)"
)
{
  if (report_verbosity > 0)
  {
    report = '\n  Version source    : ' + source +
             '\n  Installed version : ' + version +
             '\n  Fixed version     : 1.3.5' + 
             '\n';

    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else if (version =~ "^(1|1\.3)($|[^0-9.])") audit(AUDIT_VER_NOT_GRANULAR, "CUPS", port, version);
else audit(AUDIT_LISTEN_NOT_VULN, "CUPS", port, version);
