#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66239);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/11/14 18:38:12 $");

  script_cve_id(
    "CVE-2011-0914",
    "CVE-2011-0915",
    "CVE-2011-0916",
    "CVE-2011-0917",
    "CVE-2011-0920",
    "CVE-2011-3575"
  );
  script_bugtraq_id(46231, 46232, 46245, 46361, 49705);
  script_osvdb_id(70851, 72160, 72161, 72557, 72565, 75575);
  script_xref(name:"EDB-ID", value:"16190");

  script_name(english:"IBM Lotus Domino 8.5.x < 8.5.3 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Lotus Domino");

  script_set_attribute(attribute:"synopsis", value:"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Lotus Domino on the remote host
is 8.5.x prior to 8.5.3, and is, therefore, affected by the following
vulnerabilities :

  - A heap-based buffer overflow error exists in the file
    ndiiop.exe related to the DIIOP implementation and GIOP
    request handling. (CVE-2011-0914)

  - A stack-based buffer overflow error exists in the file
    nrouter.exe related to the 'name' parameter in a
    'Content-Type' header and malformed Notes calendar
    meeting requests. (CVE-2011-0915)

  - A stack-based buffer overflow error exists related to
    the 'filename' parameter, MIME email messages and the
    SMTP service. (CVE-2011-0916)

  - A buffer overflow error exists in the file nLDAP.exe
    related to handling long strings in LDAP Bind
    operations. (CVE-2011-0917)

  - An authentication bypass error exists related to the
    'Remote Console' and 'UNC share pathnames'.
    (CVE-2011-0920)

  - A stack-based buffer overflow error exists in the
    function 'NSFComputeEvaluateExt' function in the file
    'Nnotes.dll' related to the 'tHPRAgentName' parameter
    in an 'fmHttpPostRequest' OpenForm action.
    (CVE-2011-3575)

Note that exploitation of several of these vulnerabilities could result
in execution of arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"http://zerodayinitiative.com/advisories/ZDI-11-047/");
  script_set_attribute(attribute:"see_also", value:"http://zerodayinitiative.com/advisories/ZDI-11-048/");
  script_set_attribute(attribute:"see_also", value:"http://zerodayinitiative.com/advisories/ZDI-11-049/");
  script_set_attribute(attribute:"see_also", value:"http://zerodayinitiative.com/advisories/ZDI-11-052/");
  script_set_attribute(attribute:"see_also", value:"http://zerodayinitiative.com/advisories/ZDI-11-110/");
  # Fix list
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8cb395e8");
  # ZDI list
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21461514");
  # http://www.research.reversingcode.com/index.php/advisories/73-ibm-ssd-1012211
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7643c792");
  script_set_attribute(attribute:"solution", value:"Upgrade to Lotus Domino 8.5.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/02/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:lotus_domino");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("domino_installed.nasl", "http_version.nasl");
  script_require_keys("Domino/Version");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


# Unless we're being paranoid, make sure a Domino web server is listening.
if (report_paranoia < 2)
{
  port = get_http_port(default:80);
  banner = get_http_banner(port:port);
  if (!banner) audit(AUDIT_NO_BANNER, port);
  if ("Domino" >!< banner) audit(AUDIT_NOT_LISTEN, "IBM Lotus Domino", port);
}
else port = 0;

# Check the version of Domino installed.
ver = get_kb_item_or_exit("Domino/Version");

# Check that version is granular enough
if (ver == "8") exit(1, "The version "+ver+" on port "+port+" is not granular enough to make a determination.");

# Check that version is 8.5.x
if (ver !~ "^8\.5($|[^0-9])") audit(AUDIT_NOT_LISTEN, "IBM Lotus Domino 8.5.x", port);

# Affected 8.5 < 8.5.3
if (
  ver == "8.5" ||
  ver =~ "^8\.5 FP[0-9]" ||
  ver =~ "^8\.5\.[0-2]($|[^0-9])"
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n' +
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : 8.5.3' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, "IBM Lotus Domino", port, ver);
