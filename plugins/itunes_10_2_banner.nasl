#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(52535);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2016/05/16 14:02:52 $");

  script_cve_id(
    "CVE-2010-1205",
    "CVE-2010-1824",
    "CVE-2010-2249",
    "CVE-2010-4008",
    "CVE-2010-4494",
    "CVE-2011-0111",
    "CVE-2011-0112",
    "CVE-2011-0113",
    "CVE-2011-0114",
    "CVE-2011-0115",
    "CVE-2011-0116",
    "CVE-2011-0117",
    "CVE-2011-0118",
    "CVE-2011-0119",
    "CVE-2011-0120",
    "CVE-2011-0121",
    "CVE-2011-0122",
    "CVE-2011-0123",
    "CVE-2011-0124",
    "CVE-2011-0125",
    "CVE-2011-0126",
    "CVE-2011-0127",
    "CVE-2011-0128",
    "CVE-2011-0129",
    "CVE-2011-0130",
    "CVE-2011-0131",
    "CVE-2011-0132",
    "CVE-2011-0133",
    "CVE-2011-0134",
    "CVE-2011-0135",
    "CVE-2011-0136",
    "CVE-2011-0137",
    "CVE-2011-0138",
    "CVE-2011-0139",
    "CVE-2011-0140",
    "CVE-2011-0141",
    "CVE-2011-0142",
    "CVE-2011-0143",
    "CVE-2011-0144",
    "CVE-2011-0145",
    "CVE-2011-0146",
    "CVE-2011-0147",
    "CVE-2011-0148",
    "CVE-2011-0149",
    "CVE-2011-0150",
    "CVE-2011-0151",
    "CVE-2011-0152",
    "CVE-2011-0153",
    "CVE-2011-0154",
    "CVE-2011-0155",
    "CVE-2011-0156",
    "CVE-2011-0164",
    "CVE-2011-0165",
    "CVE-2011-0168",
    "CVE-2011-0170",
    "CVE-2011-0191",
    "CVE-2011-0192"
  );
  script_bugtraq_id(
    41174,
    44779,
    46657,
    46658,
    46659,
    46677,
    46684,
    46686,
    46687,
    46688,
    46689,
    46690,
    46691,
    46692,
    46693,
    46694,
    46695,
    46696,
    46698,
    46699,
    46700,
    46701,
    46702,
    46703,
    46704,
    46705,
    46706,
    46707,
    46708,
    46709,
    46710,
    46711,
    46712,
    46713,
    46714,
    46715,
    46716,
    46717,
    46718,
    46719,
    46720,
    46721,
    46722,
    46723,
    46724,
    46725,
    46726,
    46727,
    46728,
    46744,
    46745,
    46746,
    46747,
    46748,
    46749
  );
  script_osvdb_id(
    65852,
    65853,
    69163,
    69164,
    69165,
    69170,
    69205,
    69671,
    70105,
    70106,
    70454,
    70456,
    70461,
    70465,
    70466,
    70990,
    71257,
    71495,
    71496,
    71498,
    71499,
    71501,
    71502,
    71503,
    71504,
    71506,
    71508,
    71509,
    71510,
    71511,
    71512,
    71513,
    71514,
    71515,
    71516,
    71517,
    71519,
    71521,
    71524,
    71525,
    71527,
    71528,
    71529,
    71530,
    71532,
    71533,
    71534,
    71535,
    71536,
    71537,
    71539,
    71541,
    71542,
    71547
  );

  script_name(english:"Apple iTunes < 10.2 Multiple Vulnerabilities (uncredentialed check)");
  script_summary(english:"Checks the version of iTunes.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a multimedia application that has multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apple iTunes on the remote host is prior to version
10.2. It is, therefore, affected by multiple vulnerabilities in the
WebKit, ImageIO, and libxml components. Note that these only affect
iTunes for Windows.");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT4554");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2011/Mar/msg00000.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Apple iTunes 10.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/06/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:itunes");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_family(english:"Peer-To-Peer File Sharing");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

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

fixed_version = "10.2";

if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report = '\n  Version source    : ' + source +
             '\n  Installed version : ' + version +
             '\n  Fixed version     : ' + fixed_version + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, "iTunes", port, version);
