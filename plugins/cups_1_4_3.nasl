#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(45554);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/11/17 21:38:53 $");

  script_cve_id("CVE-2009-3553", "CVE-2010-0393");
  script_bugtraq_id(37048, 38524);
  script_osvdb_id(60204, 62715);

  script_name(english:"CUPS < 1.4.3 Multiple Vulnerabilities");
  script_summary(english:"Checks CUPS server version");

  script_set_attribute(attribute:"synopsis", value:"The remote printer service is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of CUPS installed on the remote
host is earlier than 1.4.3. Such versions are affected by several
vulnerabilities :

  - A pointer use-after-free vulnerability exists in the
    abstract file descriptor handling code in the
    'cupsdDoSelect' function in scheduler/select.c. A remote
    attacker may be able to leverage this to hang or crash
    the cupsd daemon by disconnecting while receiving a
    listing with a large number of print jobs. (STR #3200)

  - The lppasswd utility, when its setuid bit is enabled,
    allowing a local user to elevaate privileges because it
    uses an environment variable to override CUPS' default
    directories and determine the location of a file with
    localized message strings. (STR #3482)");
  script_set_attribute(attribute:"see_also", value:"http://www.cups.org/str.php?L3200");
  script_set_attribute(attribute:"see_also", value:"http://www.cups.org/str.php?L3482");
  script_set_attribute(attribute:"see_also", value:"http://www.cups.org/articles.php?L594");
  script_set_attribute(attribute:"solution", value:"Upgrade to CUPS version 1.4.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(264, 399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/03/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/16");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:cups");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

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
  version =~ "^1\.([0-3]|4\.[0-2])($|[^0-9])" ||
  version =~ "^1\.4(rc|b)"
)
{
  if (report_verbosity > 0)
  {
    report = '\n  Version source    : ' + source +
             '\n  Installed version : ' + version +
             '\n  Fixed version     : 1.4.3\n';

    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else if (version =~ "^(1|1\.4)($|[^0-9.])") audit(AUDIT_VER_NOT_GRANULAR, "CUPS", port, version);
else audit(AUDIT_LISTEN_NOT_VULN, "CUPS", port, version);
