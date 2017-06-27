#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(34385);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2016/11/17 21:38:53 $");

  script_cve_id("CVE-2008-3639", "CVE-2008-3640", "CVE-2008-3641");
  script_bugtraq_id(31688, 31690);
  script_osvdb_id(49130, 49131, 49132);
  script_xref(name:"Secunia", value:"32226");

  script_name(english:"CUPS < 1.3.9 Multiple Vulnerabilities");
  script_summary(english:"Checks CUPS server version");

  script_set_attribute(attribute:"synopsis", value:"The remote printer service is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of CUPS installed on the remote
host is earlier than 1.3.9. Such versions are affected by several
issues :

  - The HP-GL/2 filter does not adequately check the ranges
    on the pen width and pen color opcodes that allows an
    attacker to overwrite memory addresses with arbitrary
    data, which may result in execution of arbitrary code
    (STR #2911).

  - There is a heap-based buffer overflow in the SGI file
    format parsing module that can be triggered with
    malformed Run Length Encoded (RLE) data to execute
    arbitrary code (STR #2918).

  - There is an integer overflow vulnerability in the
    'WriteProlog()' function in the 'texttops'
    application that can be triggered when calculating
    the page size used for storing PostScript data to
    execute arbitrary code (STR #2919).");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-08-067/");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2008/Oct/175");
  # http://www.verisigninc.com/en_US/products-and-services/network-intelligence-availability/idefense/public-vulnerability-reports/articles/index.xhtml?id=752
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d39dc47a");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2008/Nov/13");
  # http://www.verisigninc.com/en_US/products-and-services/network-intelligence-availability/idefense/public-vulnerability-reports/articles/index.xhtml?id=753
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?12e95e4f");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2008/Nov/14");
  script_set_attribute(attribute:"see_also", value:"http://www.cups.org/str.php?L2911");
  script_set_attribute(attribute:"see_also", value:"http://www.cups.org/str.php?L2918");
  script_set_attribute(attribute:"see_also", value:"http://www.cups.org/str.php?L2919");
  script_set_attribute(attribute:"see_also", value:"http://www.cups.org/articles.php?L575");
  script_set_attribute(attribute:"solution", value:"Upgrade to CUPS version 1.3.9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(119, 189, 399);

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/10/10");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:cups");
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
  version =~ "^1\.([0-2]|3\.[0-8])($|[^0-9])" ||
  version =~ "^1\.3(rc|b)"
)
{
  if (report_verbosity > 0)
  {
    report = '\n  Version source    : ' + source +
             '\n  Installed version : ' + version +
             '\n  Fixed version     : 1.3.9\n';

    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else if (version =~ "^(1|1\.3)($|[^0-9.])") audit(AUDIT_VER_NOT_GRANULAR, "CUPS", port, version);
else audit(AUDIT_LISTEN_NOT_VULN, "CUPS", port, version);
