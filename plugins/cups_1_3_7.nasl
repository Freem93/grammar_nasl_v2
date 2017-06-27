#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31730);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/05/04 18:02:14 $");

  script_cve_id("CVE-2008-0047", "CVE-2008-1373");
  script_bugtraq_id(28307, 28544);
  script_osvdb_id(43376, 44160, 48699);

  script_name(english:"CUPS < 1.3.7 Multiple Vulnerabilities");
  script_summary(english:"Checks CUPS server version");

  script_set_attribute(attribute:"synopsis", value:"The remote printer service is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of CUPS installed on the remote
host is affected by several issues :

  - A buffer overflow exists in 'cgiCompileSearch' that
    could lead to arbitrary code execution (STR #2729).

  - A GIF image filter overflow exists involving 'code_size'
    value from a user-supplied GIF image used in
    'gif_read_lzw' (STR #2765).

  - A temporary file with Samba credentials may be left
    behind by cupsaddsmb if no Windows drivers were
    installed (STR #2779).");
  script_set_attribute(attribute:"see_also", value:"http://www.cups.org/str.php?L2729");
  script_set_attribute(attribute:"see_also", value:"http://www.cups.org/str.php?L2765" );
  script_set_attribute(attribute:"see_also", value:"http://www.cups.org/articles.php?L537" );
  script_set_attribute(attribute:"solution", value:"Upgrade to CUPS version 1.3.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/04/03");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cups:cups");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

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

if (
  version =~ "^1\.([0-2]|3\.[0-6])($|[^0-9])" ||
  version =~ "^1\.3(rc|b)"
)
{
  if (report_verbosity > 0)
  {
    report = '\n  Version source    : ' + source +
             '\n  Installed version : ' + version +
             '\n  Fixed version     : 1.3.7\n';

    security_note(port:port, extra:report);
  }
  else security_note(port);
  exit(0);
}
else if (version =~ "^(1|1\.3)($|[^0-9.])") audit(AUDIT_VER_NOT_GRANULAR, "CUPS", port, version);
else audit(AUDIT_LISTEN_NOT_VULN, "CUPS", port, version);
