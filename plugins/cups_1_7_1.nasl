#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71977);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/08/12 15:38:43 $");

  script_cve_id("CVE-2013-6891");
  script_osvdb_id(101860);
  script_bugtraq_id(64985);

  script_name(english:"CUPS 1.6.x >= 1.6.4 / 1.7.x < 1.7.1 lppasswd Information Disclosure");
  script_summary(english:"Checks CUPS server version");

  script_set_attribute(attribute:"synopsis", value:
"The remote print service is potentially affected by an information
disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of CUPS installed on the remote
host is 1.6.x greater or equal to 1.6.4 or 1.7.x earlier than 1.7.1.
It is, therefore, potentially affected by an information disclosure
vulnerability related to the 'lppasswd' binary, setuid settings, and
the use of '~/.cups/client.conf' files that could allow a local
attacker to obtain contents from arbitrary files in certain
configurations.");
  script_set_attribute(attribute:"see_also", value:"http://www.cups.org/str.php?L4319");
  script_set_attribute(attribute:"see_also", value:"https://www.cups.org/blog.php?L704");
  script_set_attribute(attribute:"solution", value:"Upgrade to CUPS version 1.7.1 or later, or apply the vendor patch.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/15");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:cups");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "cups_1_3_5.nasl");
  script_require_keys("www/cups", "Settings/ParanoidReport");
  script_require_ports("Services/www", 631);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:631, embedded:TRUE);
get_kb_item_or_exit("www/"+port+"/cups/running");

version = get_kb_item_or_exit("cups/"+port+"/version");
source  = get_kb_item_or_exit("cups/"+port+"/source");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (version =~ "^(1|1\.[67])($|[^0-9br.])") audit(AUDIT_VER_NOT_GRANULAR, "CUPS", port, version);

# Affected :
# 1.6.x >= 1.6.4
# 1.7.x < 1.7.1
if (
  version =~ "^1\.6\.([4-9]|[0-9][0-9])($|[^0-9.])" ||
  version =~ "^1\.7\.0($|[^0-9.])" ||
  version =~ "^1\.7(rc|b)"
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 1.7.1' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "CUPS", port, version);
