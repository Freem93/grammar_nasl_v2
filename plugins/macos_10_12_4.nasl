#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99134);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/05/19 14:17:02 $");

  script_cve_id(
    "CVE-2016-0736",
    "CVE-2016-2161",
    "CVE-2016-3619",
    "CVE-2016-5387",
    "CVE-2016-5636",
    "CVE-2016-7056",
    "CVE-2016-7585",
    "CVE-2016-7922",
    "CVE-2016-7923",
    "CVE-2016-7924",
    "CVE-2016-7925",
    "CVE-2016-7926",
    "CVE-2016-7927",
    "CVE-2016-7928",
    "CVE-2016-7929",
    "CVE-2016-7930",
    "CVE-2016-7931",
    "CVE-2016-7932",
    "CVE-2016-7933",
    "CVE-2016-7934",
    "CVE-2016-7935",
    "CVE-2016-7936",
    "CVE-2016-7937",
    "CVE-2016-7938",
    "CVE-2016-7939",
    "CVE-2016-7940",
    "CVE-2016-7973",
    "CVE-2016-7974",
    "CVE-2016-7975",
    "CVE-2016-7983",
    "CVE-2016-7984",
    "CVE-2016-7985",
    "CVE-2016-7986",
    "CVE-2016-7992",
    "CVE-2016-7993",
    "CVE-2016-8574",
    "CVE-2016-8575",
    "CVE-2016-8740",
    "CVE-2016-8743",
    "CVE-2016-9533",
    "CVE-2016-9535",
    "CVE-2016-9536",
    "CVE-2016-9537",
    "CVE-2016-9538",
    "CVE-2016-9539",
    "CVE-2016-9540",
    "CVE-2016-9586",
    "CVE-2016-9935",
    "CVE-2016-10009",
    "CVE-2016-10010",
    "CVE-2016-10011",
    "CVE-2016-10012",
    "CVE-2016-10158",
    "CVE-2016-10159",
    "CVE-2016-10160",
    "CVE-2016-10161",
    "CVE-2017-2379",
    "CVE-2017-2381",
    "CVE-2017-2388",
    "CVE-2017-2390",
    "CVE-2017-2392",
    "CVE-2017-2398",
    "CVE-2017-2401",
    "CVE-2017-2402",
    "CVE-2017-2403",
    "CVE-2017-2406",
    "CVE-2017-2407",
    "CVE-2017-2408",
    "CVE-2017-2409",
    "CVE-2017-2410",
    "CVE-2017-2413",
    "CVE-2017-2416",
    "CVE-2017-2417",
    "CVE-2017-2418",
    "CVE-2017-2420",
    "CVE-2017-2421",
    "CVE-2017-2422",
    "CVE-2017-2423",
    "CVE-2017-2425",
    "CVE-2017-2426",
    "CVE-2017-2427",
    "CVE-2017-2428",
    "CVE-2017-2429",
    "CVE-2017-2430",
    "CVE-2017-2431",
    "CVE-2017-2432",
    "CVE-2017-2435",
    "CVE-2017-2436",
    "CVE-2017-2437",
    "CVE-2017-2438",
    "CVE-2017-2439",
    "CVE-2017-2440",
    "CVE-2017-2441",
    "CVE-2017-2443",
    "CVE-2017-2448",
    "CVE-2017-2449",
    "CVE-2017-2450",
    "CVE-2017-2451",
    "CVE-2017-2456",
    "CVE-2017-2457",
    "CVE-2017-2458",
    "CVE-2017-2461",
    "CVE-2017-2462",
    "CVE-2017-2467",
    "CVE-2017-2472",
    "CVE-2017-2473",
    "CVE-2017-2474",
    "CVE-2017-2478",
    "CVE-2017-2482",
    "CVE-2017-2483",
    "CVE-2017-2485",
    "CVE-2017-2486",
    "CVE-2017-2487",
    "CVE-2017-2489",
    "CVE-2017-2490",
    "CVE-2017-5202",
    "CVE-2017-5203",
    "CVE-2017-5204",
    "CVE-2017-5205",
    "CVE-2017-5341",
    "CVE-2017-5342",
    "CVE-2017-5482",
    "CVE-2017-5483",
    "CVE-2017-5484",
    "CVE-2017-5485",
    "CVE-2017-5486",
    "CVE-2017-6974"
  );
  script_bugtraq_id(
    85919,
    91247,
    91816,
    94650,
    94742,
    94744,
    94745,
    94746,
    94747,
    94753,
    94754,
    94846,
    94968,
    94972,
    94975,
    94977,
    95019,
    95076,
    95077,
    95078,
    95375,
    95764,
    95768,
    95774,
    95783,
    95852,
    97132,
    97134,
    97137,
    97140,
    97146,
    97147,
    97300,
    97301
  );
  script_osvdb_id(
    136738,
    140125,
    141669,
    145021,
    145023,
    145751,
    145752,
    146185,
    147758,
    147779,
    148143,
    148281,
    148286,
    148338,
    148966,
    148967,
    148968,
    148975,
    149048,
    149054,
    149425,
    149623,
    149629,
    149665,
    149666,
    151088,
    151089,
    151090,
    151091,
    151092,
    151093,
    151094,
    151095,
    151096,
    151097,
    151098,
    151099,
    151100,
    151103,
    151104,
    151105,
    151106,
    151107,
    151108,
    151109,
    151110,
    151111,
    151112,
    151113,
    151114,
    151115,
    151116,
    151117,
    151119,
    151120,
    151121,
    151122,
    151123,
    151124,
    151125,
    151126,
    151128,
    151129,
    151130,
    151131,
    151132,
    154418,
    154462,
    154463,
    154464,
    154465,
    154466,
    154467,
    154468,
    154469,
    154470,
    154471,
    154472,
    154473,
    154474,
    154475,
    154476,
    154477,
    154478,
    154479,
    154480,
    154481,
    154482,
    154483,
    154484,
    154485,
    154486,
    154487,
    154488,
    154489,
    154491,
    154492,
    154493,
    154494,
    154495,
    154496,
    154497,
    154498,
    154499,
    154500,
    154501,
    154502,
    154503,
    154504,
    154505,
    154506,
    154507,
    154508,
    154509,
    154510,
    154511,
    154512,
    154513,
    154514,
    154515,
    154516,
    154517,
    154518,
    154519,
    154529,
    154758,
    154759
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2017-03-27-3");
  script_xref(name:"CERT", value:"797896");
  script_xref(name:"EDB-ID", value:"40961");
  script_xref(name:"EDB-ID", value:"40962");

  script_name(english:"macOS 10.12.x < 10.12.4 Multiple Vulnerabilities (httpoxy)");
  script_summary(english:"Checks the version of macOS.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS update that fixes multiple security
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS that is 10.12.x prior to
10.12.4. It is, therefore, affected by multiple vulnerabilities in
multiple components, some of which are remote code execution
vulnerabilities. An unauthenticated, remote attacker can exploit these
remote code execution vulnerabilities by convincing a user to visit a
specially crafted website, resulting in the execution of arbitrary
code in the context of the current user. The affected components are
as follows :

  - apache
  - apache_mod_php
  - AppleGraphicsPowerManagement
  - AppleRAID
  - Audio
  - Bluetooth
  - Carbon
  - CoreGraphics
  - CoreMedia
  - CoreText
  - curl
  - EFI
  - FinderKit
  - FontParser
  - HTTPProtocol
  - Hypervisor
  - iBooks
  - ImageIO
  - Intel Graphics Driver
  - IOATAFamily
  - IOFireWireAVC
  - IOFireWireFamily
  - Kernel
  - Keyboards
  - libarchive
  - libc++abi
  - LibreSSL
  - MCX Client
  - Menus
  - Multi-Touch
  - OpenSSH
  - OpenSSL
  - Printing
  - python
  - QuickTime
  - Security
  - SecurityFoundation
  - sudo
  - System Integrity Protection
  - tcpdump
  - tiffutil
  - WebKit");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS version 10.12.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT207615");
  # https://lists.apple.com/archives/security-announce/2017/Mar/msg00004.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ddb4db4a");
  script_set_attribute(attribute:"see_also", value:"https://httpoxy.org");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/31");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_ports("Host/MacOSX/Version", "Host/OS");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

os = get_kb_item("Host/MacOSX/Version");
if (!os)
{
  os = get_kb_item_or_exit("Host/OS");
  if ("Mac OS X" >!< os) audit(AUDIT_OS_NOT, "macOS / Mac OS X");

  c = get_kb_item("Host/OS/Confidence");
  if (c <= 70) exit(1, "Can't determine the host's OS with sufficient confidence.");
}
if (!os) audit(AUDIT_OS_NOT, "macOS / Mac OS X");

matches = eregmatch(pattern:"Mac OS X ([0-9]+(\.[0-9]+)+)", string:os);
if (isnull(matches)) exit(1, "Failed to parse the macOS / Mac OS X version ('" + os + "').");

version = matches[1];
if (version !~ "^10\.12($|[^0-9])") audit(AUDIT_OS_NOT, "Mac OS 10.12.x");

fixed_version = "10.12.4";
if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  security_report_v4(
    port:0,
    severity:SECURITY_HOLE,
    xss:TRUE,
    extra:
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version +
      '\n'
  );
}
else audit(AUDIT_INST_VER_NOT_VULN, "macOS / Mac OS X", version);
