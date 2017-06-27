#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(36183);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2016/11/17 21:38:53 $");

  script_cve_id(
    "CVE-2008-5286",
    "CVE-2009-0163",
    "CVE-2009-0164",
    "CVE-2009-0195",
    "CVE-2009-0949"
  );
  script_bugtraq_id(32518, 34571, 34665, 34791, 35169);
  script_osvdb_id(50494, 54461, 54462, 54490, 55002);
  script_xref(name:"Secunia", value:"34481");

  script_name(english:"CUPS < 1.3.10 Multiple Vulnerabilities");
  script_summary(english:"Checks CUPS server version");

  script_set_attribute(attribute:"synopsis", value:"The remote printer service is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of CUPS installed on the remote
host is earlier than 1.3.10. Such versions are affected by several
issues :

  - A potential integer overflow in the PNG image validation
    code in '_cupsImageReadPNG()' could allow an attacker to
    crash the affected service or possibly execute arbitrary
    code. (STR #2974)

  - A heap-based integer overflow exists in
    '_cupsImageReadTIFF()' due to a failure to properly
    validate the image height of a specially crafted TIFF
    file, which can be leveraged to execute arbitrary code.
    (STR #3031)

  - The web interface may be vulnerable to DNS rebinding
    attacks due to a failure to validate the HTTP Host
    header in incoming requests. (STR #3118)

  - A heap-based buffer overflow in pdftops allows remote
    attackers to execute arbitrary code via a PDF file with
    crafted JBIG2 symbol dictionary segments.
    (CVE-2009-0195)

  - Flawed 'ip' structure initialization in the function
    'ippReadIO()' could allow an anonymous remote attacker
    to crash the application via a malicious IPP request
    packet with two consecutives IPP_TAG_UNSUPPORTED tags.
    (CVE-2009-0949)");

  script_set_attribute(attribute:"see_also", value:"http://www.cups.org/str.php?L2974");
  script_set_attribute(attribute:"see_also", value:"http://www.cups.org/str.php?L3031");
  script_set_attribute(attribute:"see_also", value:"http://www.cups.org/str.php?L3118");
  script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2009-18/");
  script_set_attribute(attribute:"see_also", value:"http://www.coresecurity.com/content/AppleCUPS-null-pointer-vulnerability");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/504032/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.cups.org/articles.php?L582");
  script_set_attribute(attribute:"solution", value:"Upgrade to CUPS version 1.3.10 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(20, 119, 189, 399);

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/17");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:cups");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

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
  version =~ "^1\.([0-2]|3\.[0-9])($|[^0-9])" ||
  version =~ "^1\.3(rc|b)"
)
{
  if (report_verbosity > 0)
  {
    report = '\n  Version source    : ' + source +
             '\n  Installed version : ' + version +
             '\n  Fixed version     : 1.3.10\n';

    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else if (version =~ "^(1|1\.3)($|[^0-9.])") audit(AUDIT_VER_NOT_GRANULAR, "CUPS", port, version);
else audit(AUDIT_LISTEN_NOT_VULN, "CUPS", port, version);
