#
# (C) Tenable Network Security, Inc.
#

if (NASL_LEVEL < 3000) exit(0);    # Avoid problems with large number of xrefs.


include("compat.inc");


if (description)
{
  script_id(56470);
  script_version("$Revision: 1.46 $");
  script_cvs_date("$Date: 2016/11/23 20:31:32 $");

  script_cve_id(
    "CVE-2010-1823",
    "CVE-2011-0164",
    "CVE-2011-0200",
    "CVE-2011-0204",
    "CVE-2011-0215",
    "CVE-2011-0218",
    "CVE-2011-0221",
    "CVE-2011-0222",
    "CVE-2011-0223",
    "CVE-2011-0225",
    "CVE-2011-0232",
    "CVE-2011-0233",
    "CVE-2011-0234",
    "CVE-2011-0235",
    "CVE-2011-0237",
    "CVE-2011-0238",
    "CVE-2011-0240",
    "CVE-2011-0253",
    "CVE-2011-0254",
    "CVE-2011-0255",
    "CVE-2011-0259",
    "CVE-2011-0981",
    "CVE-2011-0983",
    "CVE-2011-1109",
    "CVE-2011-1114",
    "CVE-2011-1115",
    "CVE-2011-1117",
    "CVE-2011-1121",
    "CVE-2011-1188",
    "CVE-2011-1203",
    "CVE-2011-1204",
    "CVE-2011-1288",
    "CVE-2011-1293",
    "CVE-2011-1296",
    "CVE-2011-1440",
    "CVE-2011-1449",
    "CVE-2011-1451",
    "CVE-2011-1453",
    "CVE-2011-1457",
    "CVE-2011-1462",
    "CVE-2011-1774",
    "CVE-2011-1797",
    "CVE-2011-2338",
    "CVE-2011-2339",
    "CVE-2011-2341",
    "CVE-2011-2351",
    "CVE-2011-2352",
    "CVE-2011-2354",
    "CVE-2011-2356",
    "CVE-2011-2359",
    "CVE-2011-2788",
    "CVE-2011-2790",
    "CVE-2011-2792",
    "CVE-2011-2797",
    "CVE-2011-2799",
    "CVE-2011-2809",
    "CVE-2011-2811",
    "CVE-2011-2813",
    "CVE-2011-2814",
    "CVE-2011-2815",
    "CVE-2011-2816",
    "CVE-2011-2817",
    "CVE-2011-2818",
    "CVE-2011-2820",
    "CVE-2011-2823",
    "CVE-2011-2827",
    "CVE-2011-2831",
    "CVE-2011-3219",
    "CVE-2011-3232",
    "CVE-2011-3233",
    "CVE-2011-3234",
    "CVE-2011-3235",
    "CVE-2011-3236",
    "CVE-2011-3237",
    "CVE-2011-3238",
    "CVE-2011-3239",
    "CVE-2011-3241",
    "CVE-2011-3244",
    "CVE-2011-3252"
  );
  script_bugtraq_id(
    46262,
    46614,
    46785,
    47029,
    47604,
    48437,
    48479,
    48840,
    48856,
    48960,
    49279,
    49658,
    49850,
    50065,
    50066,
    50067,
    50068
  );
  script_osvdb_id(
    68101,
    70977,
    70980,
    71524,
    72205,
    72214,
    72216,
    72262,
    72265,
    72272,
    72276,
    72278,
    72279,
    72284,
    72303,
    72476,
    72491,
    72492,
    73364,
    73368,
    73511,
    73993,
    73997,
    73998,
    73999,
    74000,
    74001,
    74002,
    74003,
    74004,
    74005,
    74006,
    74007,
    74008,
    74009,
    74010,
    74011,
    74012,
    74013,
    74014,
    74015,
    74016,
    74229,
    74238,
    74240,
    74242,
    74247,
    74250,
    74255,
    74692,
    74698,
    75550,
    75844,
    76323,
    76336,
    76337,
    76338,
    76339,
    76340,
    76341,
    76342,
    76343,
    76344,
    76345,
    76346,
    76347,
    76348,
    76349,
    76350,
    76351,
    76352,
    76374,
    76381,
    76382,
    76383,
    76384,
    76385,
    76386,
    76387
  );
  script_xref(name:"MSVR", value:"MSVR11-001");

  script_name(english:"Apple iTunes < 10.5 Multiple Vulnerabilities (uncredentialed check)");
  script_summary(english:"Checks the version of iTunes.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a multimedia application that has multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apple iTunes on the remote host is prior to version
10.5. It is, therefore, affected by multiple vulnerabilities in the
CoreAudio, CoreFoundation, CoreMedia, ColorSync, ImageIO, and WebKit
components. Note that these only affect iTunes for Windows.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-303/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-304/");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT4981");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2011/Oct/msg00000.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Apple iTunes 10.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-11-678");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apple Safari Webkit libxslt Arbitrary File Creation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'White_Phosphorus');

script_set_attribute(attribute:"vuln_publication_date", value:"2011/10/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/12");

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

fixed_version = "10.5";

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
