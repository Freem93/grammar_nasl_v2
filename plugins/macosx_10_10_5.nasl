#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85408);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/07/18 15:54:01 $");

  script_cve_id(
    "CVE-2009-5044",
    "CVE-2009-5078",
    "CVE-2012-6685",
    "CVE-2013-1775",
    "CVE-2013-1776",
    "CVE-2013-2776",
    "CVE-2013-2777",
    "CVE-2013-7040",
    "CVE-2013-7338",
    "CVE-2013-7422",
    "CVE-2014-0067",
    "CVE-2014-0106",
    "CVE-2014-0191",
    "CVE-2014-1912",
    "CVE-2014-3581",
    "CVE-2014-3583",
    "CVE-2014-3613",
    "CVE-2014-3620",
    "CVE-2014-3660",
    "CVE-2014-3707",
    "CVE-2014-7185",
    "CVE-2014-7844",
    "CVE-2014-8109",
    "CVE-2014-8150",
    "CVE-2014-8151",
    "CVE-2014-8161",
    "CVE-2014-8767",
    "CVE-2014-8769",
    "CVE-2014-9140",
    "CVE-2014-9365",
    "CVE-2014-9680",
    "CVE-2015-0228",
    "CVE-2015-0241",
    "CVE-2015-0242",
    "CVE-2015-0243",
    "CVE-2015-0244",
    "CVE-2015-0253",
    "CVE-2015-1788",
    "CVE-2015-1789",
    "CVE-2015-1790",
    "CVE-2015-1791",
    "CVE-2015-1792",
    "CVE-2015-2783",
    "CVE-2015-2787",
    "CVE-2015-3143",
    "CVE-2015-3144",
    "CVE-2015-3145",
    "CVE-2015-3148",
    "CVE-2015-3153",
    "CVE-2015-3183",
    "CVE-2015-3185",
    "CVE-2015-3307",
    "CVE-2015-3329",
    "CVE-2015-3330",
    "CVE-2015-3729",
    "CVE-2015-3730",
    "CVE-2015-3731",
    "CVE-2015-3732",
    "CVE-2015-3733",
    "CVE-2015-3734",
    "CVE-2015-3735",
    "CVE-2015-3736",
    "CVE-2015-3737",
    "CVE-2015-3738",
    "CVE-2015-3739",
    "CVE-2015-3740",
    "CVE-2015-3741",
    "CVE-2015-3742",
    "CVE-2015-3743",
    "CVE-2015-3744",
    "CVE-2015-3745",
    "CVE-2015-3746",
    "CVE-2015-3747",
    "CVE-2015-3748",
    "CVE-2015-3749",
    "CVE-2015-3750",
    "CVE-2015-3751",
    "CVE-2015-3752",
    "CVE-2015-3753",
    "CVE-2015-3754",
    "CVE-2015-3755",
    "CVE-2015-3757",
    "CVE-2015-3760",
    "CVE-2015-3761",
    "CVE-2015-3762",
    "CVE-2015-3764",
    "CVE-2015-3765",
    "CVE-2015-3766",
    "CVE-2015-3767",
    "CVE-2015-3768",
    "CVE-2015-3769",
    "CVE-2015-3770",
    "CVE-2015-3771",
    "CVE-2015-3772",
    "CVE-2015-3773",
    "CVE-2015-3774",
    "CVE-2015-3775",
    "CVE-2015-3776",
    "CVE-2015-3777",
    "CVE-2015-3778",
    "CVE-2015-3779",
    "CVE-2015-3780",
    "CVE-2015-3781",
    "CVE-2015-3782",
    "CVE-2015-3783",
    "CVE-2015-3784",
    "CVE-2015-3786",
    "CVE-2015-3787",
    "CVE-2015-3788",
    "CVE-2015-3789",
    "CVE-2015-3790",
    "CVE-2015-3791",
    "CVE-2015-3792",
    "CVE-2015-3794",
    "CVE-2015-3795",
    "CVE-2015-3796",
    "CVE-2015-3797",
    "CVE-2015-3798",
    "CVE-2015-3799",
    "CVE-2015-3800",
    "CVE-2015-3802",
    "CVE-2015-3803",
    "CVE-2015-3804",
    "CVE-2015-3805",
    "CVE-2015-3806",
    "CVE-2015-3807",
    "CVE-2015-4021",
    "CVE-2015-4022",
    "CVE-2015-4024",
    "CVE-2015-4025",
    "CVE-2015-4026",
    "CVE-2015-4147",
    "CVE-2015-4148",
    "CVE-2015-5600",
    "CVE-2015-5747",
    "CVE-2015-5748",
    "CVE-2015-5750",
    "CVE-2015-5751",
    "CVE-2015-5753",
    "CVE-2015-5754",
    "CVE-2015-5755",
    "CVE-2015-5756",
    "CVE-2015-5757",
    "CVE-2015-5758",
    "CVE-2015-5761",
    "CVE-2015-5763",
    "CVE-2015-5768",
    "CVE-2015-5771",
    "CVE-2015-5772",
    "CVE-2015-5773",
    "CVE-2015-5774",
    "CVE-2015-5775",
    "CVE-2015-5776",
    "CVE-2015-5777",
    "CVE-2015-5778",
    "CVE-2015-5779",
    "CVE-2015-5781",
    "CVE-2015-5782",
    "CVE-2015-5783",
    "CVE-2015-5784"
  );
  script_bugtraq_id(
    36381,
    58203,
    58207,
    62741,
    64194,
    65179,
    65379,
    65721,
    65997,
    67233,
    69742,
    69748,
    70089,
    70644,
    70988,
    71150,
    71153,
    71468,
    71639,
    71656,
    71657,
    71701,
    71964,
    72538,
    72540,
    72542,
    72543,
    72649,
    72981,
    73040,
    73041,
    73357,
    73431,
    74174,
    74204,
    74239,
    74240,
    74299,
    74300,
    74301,
    74303,
    74408,
    74700,
    74703,
    74902,
    74903,
    74904,
    75056,
    75103,
    75154,
    75156,
    75157,
    75158,
    75161,
    75704,
    75963,
    75964,
    75965,
    75990,
    76337,
    76338,
    76339,
    76340,
    76341,
    76342,
    76343,
    76344
  );
  script_osvdb_id(
    73111,
    74382,
    90661,
    90677,
    90946,
    101258,
    102599,
    102929,
    103550,
    104086,
    106710,
    111287,
    111294,
    112028,
    112168,
    113389,
    114163,
    114570,
    114738,
    114740,
    115292,
    115375,
    115871,
    115954,
    116807,
    116819,
    117830,
    118033,
    118034,
    118035,
    118036,
    118037,
    118038,
    118397,
    119066,
    119774,
    119904,
    120925,
    120930,
    120938,
    121128,
    121129,
    121130,
    121131,
    121452,
    122125,
    122126,
    122127,
    122257,
    122261,
    122268,
    124938,
    126104,
    126105,
    126106,
    126107,
    126108,
    126109,
    126110,
    126111,
    126112,
    126113,
    126114,
    126115,
    126116,
    126117,
    126118,
    126119,
    126120,
    126121,
    126122,
    126123,
    126124,
    126125,
    126126,
    126127,
    126128,
    126129,
    126130,
    126188,
    126189,
    126190,
    126191,
    126192,
    126193,
    126194,
    126195,
    126196,
    126197,
    126198,
    126199,
    126200,
    126201,
    126202,
    126203,
    126204,
    126205,
    126206,
    126207,
    126208,
    126209,
    126210,
    126211,
    126212,
    126213,
    126214,
    126215,
    126216,
    126217,
    126218,
    126219,
    126220,
    126221,
    126222,
    126223,
    126224,
    126225,
    126226,
    126227,
    126228,
    126229,
    126230,
    126231,
    126232,
    126233,
    126234,
    126235,
    126236,
    126237,
    126238,
    126239,
    126240,
    126241,
    126242,
    126243,
    126244,
    126245,
    126246,
    126247,
    126248,
    126249,
    126250,
    126251,
    126252,
    126253,
    126254,
    126255,
    126256,
    126257,
    126258
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2015-08-13-2");

  script_name(english:"Mac OS X 10.10.x < 10.10.5 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Mac OS X.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X update that fixes multiple
security vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X 10.10.x that is prior
to 10.10.5. It is, therefore, affected by multiple vulnerabilities in
the following components :

  - apache
  - apache_mod_php
  - Apple ID OD Plug-in
  - AppleGraphicsControl
  - Bluetooth
  - bootp
  - CloudKit
  - CoreMedia Playback
  - CoreText
  - curl
  - Data Detectors Engine
  - Date & Time pref pane
  - Dictionary Application
  - DiskImages
  - dyld
  - FontParser
  - groff
  - ImageIO
  - Install Framework Legacy
  - IOFireWireFamily
  - IOGraphics
  - IOHIDFamily
  - Kernel
  - Libc
  - Libinfo
  - libpthread
  - libxml2
  - libxpc
  - mail_cmds
  - Notification Center OSX
  - ntfs
  - OpenSSH
  - OpenSSL
  - perl
  - PostgreSQL
  - python
  - QL Office
  - Quartz Composer Framework
  - Quick Look
  - QuickTime 7
  - SceneKit
  - Security
  - SMBClient
  - Speech UI
  - sudo
  - tcpdump
  - Text Formats
  - udf 

Note that successful exploitation of the most serious issues can
result in arbitrary code execution.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT205031");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mac OS X 10.10.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Mac OS X Sudo Password Bypass');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/07/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/17");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
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
if (!ereg(pattern:"^10\.10([^0-9]|$)", string:version)) audit(AUDIT_OS_NOT, "Mac OS X 10.10", "Mac OS X "+version);

fixed_version = "10.10.5";
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
