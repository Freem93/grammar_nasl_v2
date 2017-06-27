#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70589);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/08/03 13:57:40 $");

  script_cve_id(
    "CVE-2011-3102",
    "CVE-2012-0841",
    "CVE-2012-2807",
    "CVE-2012-2825",
    "CVE-2012-2870",
    "CVE-2012-2871",
    "CVE-2012-5134",
    "CVE-2013-1024",
    "CVE-2013-1037",
    "CVE-2013-1038",
    "CVE-2013-1039",
    "CVE-2013-1040",
    "CVE-2013-1041",
    "CVE-2013-1042",
    "CVE-2013-1043",
    "CVE-2013-1044",
    "CVE-2013-1045",
    "CVE-2013-1046",
    "CVE-2013-1047",
    "CVE-2013-2842",
    "CVE-2013-5125",
    "CVE-2013-5126",
    "CVE-2013-5127",
    "CVE-2013-5128"
  );
  script_bugtraq_id(
    52107,
    53540,
    54203,
    54718,
    55331,
    56684,
    60067,
    60368,
    62551,
    62553,
    62554,
    62556,
    62557,
    62558,
    62559,
    62560,
    62563,
    62565,
    62567,
    62568,
    62569,
    62570,
    62571
  );
  script_osvdb_id(
    79437,
    81964,
    83255,
    83266,
    85035,
    85036,
    87882,
    91608,
    92818,
    93926,
    97488,
    97489,
    97490,
    97491,
    97492,
    97493,
    97494,
    97495,
    97496,
    97497,
    97498,
    97499,
    97500,
    97501,
    97502
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2013-10-22-8");

  script_name(english:"Apple iTunes < 11.1.2 Multiple Vulnerabilities (uncredentialed check)");
  script_summary(english:"Checks the version of iTunes.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a multimedia application that has multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apple iTunes on the remote host is prior to version
11.1.2. It is, therefore, affected by multiple vulnerabilities :

  - An uninitialized memory access error exists in the
    handling of text tracks. By using a specially crafted
    movie file, a remote attacker can exploit this to cause
    a denial of service or execute arbitrary code.
    (CVE-2013-1024)

  - The included versions of the WebKit, libxml, and libxslt
    components in iTunes contain several errors that can
    lead to memory corruption and arbitrary code execution.
    The vendor states that one possible vector is a man-in-
    the-middle attack while the application browses the
    'iTunes Store'.
    (CVE-2011-3102, CVE-2012-0841, CVE-2012-2807,
    CVE-2012-2825, CVE-2012-2870, CVE-2012-2871,
    CVE-2012-5134, CVE-2013-1037, CVE-2013-1038,
    CVE-2013-1039, CVE-2013-1040, CVE-2013-1041,
    CVE-2013-1042, CVE-2013-1043, CVE-2013-1044,
    CVE-2013-1045, CVE-2013-1046, CVE-2013-1047,
    CVE-2013-2842, CVE-2013-5125, CVE-2013-5126,
    CVE-2013-5127, CVE-2013-5128)");
  # script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT6001");
  # https://web.archive.org/web/20131026094619/http://support.apple.com/kb/HT6001
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c88f1609");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2013/Oct/msg00009.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Apple iTunes 11.1.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:itunes");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_family(english:"Peer-To-Peer File Sharing");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("itunes_sharing.nasl");
  script_require_keys("iTunes/sharing");
  script_require_ports("Services/www", 3689);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:3689, embedded:TRUE, ignore_broken:TRUE);

get_kb_item_or_exit("iTunes/" + port + "/enabled");

type = get_kb_item_or_exit("iTunes/" + port + "/type");
source = get_kb_item_or_exit("iTunes/" + port + "/source");
version = get_kb_item_or_exit("iTunes/" + port + "/version");

if (type != 'Windows') audit(AUDIT_OS_NOT, "Windows");

fixed_version = "11.1.2";

if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report = '\n  Version source    : ' + source +
             '\n  Installed version : ' + version +
             '\n  Fixed version     : ' + fixed_version + '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, "iTunes", port, version);
