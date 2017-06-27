#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86270);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/11/28 21:06:37 $");

  script_cve_id(
    "CVE-2013-3951",
    "CVE-2014-2532",
    "CVE-2014-3618",
    "CVE-2014-6277",
    "CVE-2014-7186",
    "CVE-2014-7187",
    "CVE-2014-8080",
    "CVE-2014-8090",
    "CVE-2014-8146",
    "CVE-2014-8147",
    "CVE-2014-8611",
    "CVE-2014-9425",
    "CVE-2014-9427",
    "CVE-2014-9652",
    "CVE-2014-9705",
    "CVE-2014-9709",
    "CVE-2015-0231",
    "CVE-2015-0232",
    "CVE-2015-0235",
    "CVE-2015-0273",
    "CVE-2015-0286",
    "CVE-2015-0287",
    "CVE-2015-1351",
    "CVE-2015-1352",
    "CVE-2015-1855",
    "CVE-2015-2301",
    "CVE-2015-2305",
    "CVE-2015-2331",
    "CVE-2015-2348",
    "CVE-2015-2783",
    "CVE-2015-2787",
    "CVE-2015-3329",
    "CVE-2015-3330",
    "CVE-2015-3414",
    "CVE-2015-3415",
    "CVE-2015-3416",
    "CVE-2015-3785",
    "CVE-2015-3801",
    "CVE-2015-5522",
    "CVE-2015-5523",
    "CVE-2015-5764",
    "CVE-2015-5765",
    "CVE-2015-5767",
    "CVE-2015-5780",
    "CVE-2015-5788",
    "CVE-2015-5789",
    "CVE-2015-5790",
    "CVE-2015-5791",
    "CVE-2015-5792",
    "CVE-2015-5793",
    "CVE-2015-5794",
    "CVE-2015-5795",
    "CVE-2015-5796",
    "CVE-2015-5797",
    "CVE-2015-5798",
    "CVE-2015-5799",
    "CVE-2015-5800",
    "CVE-2015-5801",
    "CVE-2015-5802",
    "CVE-2015-5803",
    "CVE-2015-5804",
    "CVE-2015-5805",
    "CVE-2015-5806",
    "CVE-2015-5807",
    "CVE-2015-5808",
    "CVE-2015-5809",
    "CVE-2015-5810",
    "CVE-2015-5811",
    "CVE-2015-5812",
    "CVE-2015-5813",
    "CVE-2015-5814",
    "CVE-2015-5815",
    "CVE-2015-5816",
    "CVE-2015-5817",
    "CVE-2015-5818",
    "CVE-2015-5819",
    "CVE-2015-5820",
    "CVE-2015-5821",
    "CVE-2015-5822",
    "CVE-2015-5823",
    "CVE-2015-5824",
    "CVE-2015-5825",
    "CVE-2015-5826",
    "CVE-2015-5827",
    "CVE-2015-5828",
    "CVE-2015-5830",
    "CVE-2015-5831",
    "CVE-2015-5833",
    "CVE-2015-5836",
    "CVE-2015-5839",
    "CVE-2015-5840",
    "CVE-2015-5841",
    "CVE-2015-5842",
    "CVE-2015-5847",
    "CVE-2015-5849",
    "CVE-2015-5851",
    "CVE-2015-5853",
    "CVE-2015-5854",
    "CVE-2015-5855",
    "CVE-2015-5858",
    "CVE-2015-5860",
    "CVE-2015-5862",
    "CVE-2015-5863",
    "CVE-2015-5864",
    "CVE-2015-5865",
    "CVE-2015-5866",
    "CVE-2015-5867",
    "CVE-2015-5868",
    "CVE-2015-5869",
    "CVE-2015-5870",
    "CVE-2015-5871",
    "CVE-2015-5872",
    "CVE-2015-5873",
    "CVE-2015-5874",
    "CVE-2015-5875",
    "CVE-2015-5876",
    "CVE-2015-5877",
    "CVE-2015-5878",
    "CVE-2015-5879",
    "CVE-2015-5881",
    "CVE-2015-5882",
    "CVE-2015-5883",
    "CVE-2015-5884",
    "CVE-2015-5885",
    "CVE-2015-5887",
    "CVE-2015-5888",
    "CVE-2015-5889",
    "CVE-2015-5890",
    "CVE-2015-5891",
    "CVE-2015-5893",
    "CVE-2015-5894",
    "CVE-2015-5896",
    "CVE-2015-5897",
    "CVE-2015-5899",
    "CVE-2015-5900",
    "CVE-2015-5901",
    "CVE-2015-5902",
    "CVE-2015-5903",
    "CVE-2015-5912",
    "CVE-2015-5913",
    "CVE-2015-5914",
    "CVE-2015-5915",
    "CVE-2015-5917",
    "CVE-2015-5922"
  );
  script_bugtraq_id(
    60440,
    66355,
    69573,
    70152,
    70154,
    70165,
    70935,
    71230,
    71621,
    71800,
    71833,
    71929,
    71932,
    72325,
    72505,
    72539,
    72541,
    72611,
    72701,
    73031,
    73037,
    73182,
    73225,
    73227,
    73306,
    73431,
    73434,
    74204,
    74228,
    74239,
    74240,
    74446,
    74457,
    75037,
    76763,
    76764,
    76765,
    76766
  );
  script_osvdb_id(
    93960,
    104578,
    112096,
    112097,
    112158,
    113747,
    114641,
    115619,
    116020,
    116499,
    116621,
    117467,
    117588,
    117589,
    118582,
    118589,
    119650,
    119755,
    119761,
    119773,
    119774,
    120541,
    120909,
    120925,
    120930,
    120938,
    120943,
    120944,
    121624,
    121625,
    127584,
    127585,
    127586,
    127588,
    127589,
    127590,
    127591,
    127592,
    127594,
    127596,
    127597,
    127598,
    127599,
    127602,
    127606,
    127607,
    127608,
    127613,
    127614,
    127615,
    127616,
    127617,
    127618,
    127619,
    127620,
    127621,
    127622,
    127623,
    127624,
    127625,
    127626,
    127629,
    127631,
    127632,
    127637,
    127638,
    127639,
    127651,
    127652,
    127653,
    127654,
    127655,
    127656,
    127657,
    127658,
    127659,
    127660,
    127661,
    127662,
    127663,
    127664,
    127665,
    127666,
    127667,
    127668,
    127670,
    127671,
    127672,
    127673,
    127674,
    127675,
    127676,
    127677,
    127680,
    127681,
    127683,
    128272,
    128273,
    128274,
    128275,
    128276,
    128277,
    128278,
    128279,
    128280,
    128281,
    128282,
    128283,
    128284,
    128285,
    128286,
    128287,
    128288,
    128289,
    128290,
    128291,
    128292,
    128293,
    128294,
    128295,
    128296,
    128297,
    128298,
    128299,
    128300,
    128301,
    128302,
    128303,
    128304,
    128305,
    128306,
    128307,
    128308,
    128309,
    128310
  );
  script_xref(name:"CERT", value:"967332");
  script_xref(name:"IAVA", value:"2014-A-0142");
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2015-09-30-3");

  script_name(english:"Mac OS X < 10.11 Multiple Vulnerabilities (GHOST)");
  script_summary(english:"Checks the version of Mac OS X.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X update that fixes multiple
security vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X that is 10.6.8 or
later but prior to 10.11. It is, therefore, affected by multiple
vulnerabilities in the following components :

  - Address Book
  - AirScan
  - apache_mod_php
  - Apple Online Store Kit
  - AppleEvents
  - Audio
  - bash
  - Certificate Trust Policy
  - CFNetwork Cookies
  - CFNetwork FTPProtocol
  - CFNetwork HTTPProtocol
  - CFNetwork Proxies
  - CFNetwork SSL
  - CoreCrypto
  - CoreText
  - Dev Tools
  - Disk Images
  - dyld
  - EFI
  - Finder
  - Game Center
  - Heimdal
  - ICU
  - Install Framework Legacy
  - Intel Graphics Driver
  - IOAudioFamily
  - IOGraphics
  - IOHIDFamily
  - IOStorageFamily
  - Kernel
  - libc
  - libpthread
  - libxpc
  - Login Window
  - lukemftpd
  - Mail
  - Multipeer Connectivity
  - NetworkExtension
  - Notes
  - OpenSSH
  - OpenSSL
  - procmail
  - remote_cmds
  - removefile
  - Ruby
  - Safari
  - Safari Downloads
  - Safari Extensions
  - Safari Safe Browsing
  - Security
  - SMB
  - SQLite
  - Telephony
  - Terminal
  - tidy
  - Time Machine
  - WebKit
  - WebKit CSS
  - WebKit JavaScript Bindings
  - WebKit Page Loading
  - WebKit Plug-ins

Note that successful exploitation of the most serious issues can
result in arbitrary code execution.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT205267");
  # https://lists.apple.com/archives/security-announce/2015/Sep/msg00008.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?76b3b492");
  # https://www.qualys.com/research/security-advisories/GHOST-CVE-2015-0235.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c7a6ddbd");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mac OS X 10.11 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Mac OS X 10.9.5 / 10.10.5 - rsh/libmalloc Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/04/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/05");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

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
  if ("Mac OS X" >!< os) audit(AUDIT_OS_NOT, "Mac OS X");

  c = get_kb_item("Host/OS/Confidence");
  if (c <= 70) exit(1, "Can't determine the host's OS with sufficient confidence.");
}
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

match = eregmatch(pattern:"Mac OS X ([0-9]+(\.[0-9]+)+)", string:os);
if (isnull(match)) exit(1, "Failed to parse the Mac OS X version ('" + os + "').");

version = match[1];
if (
  version !~ "^10\.6\.([89]|[1-9][0-9]+)" &&
  version !~ "^10\.([7-9]|10)\."
) audit(AUDIT_OS_NOT, "Mac OS X 10.6.8 or later", "Mac OS X "+version);

fixed_version = "10.11";
if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
    {
      report = '\n  Installed version : ' + version +
               '\n  Fixed version     : ' + fixed_version +
               '\n';
      security_hole(port:0, extra:report);
    }
    else security_hole(0);
    exit(0);
}
else exit(0, "The host is not affected since it is running Mac OS X "+version+".");
