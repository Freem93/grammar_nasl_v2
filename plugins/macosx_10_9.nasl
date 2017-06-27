#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70561);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/04/21 16:08:19 $");

  script_cve_id(
    "CVE-2011-2391",
    "CVE-2011-3389",
    "CVE-2011-3427",
    "CVE-2011-4944",
    "CVE-2012-0845",
    "CVE-2012-0876",
    "CVE-2012-1150",
    "CVE-2013-0249",
    "CVE-2013-1667",
    "CVE-2013-1944",
    "CVE-2013-3950",
    "CVE-2013-3954",
    "CVE-2013-4073",
    "CVE-2013-5135",
    "CVE-2013-5138",
    "CVE-2013-5139",
    "CVE-2013-5141",
    "CVE-2013-5142",
    "CVE-2013-5145",
    "CVE-2013-5165",
    "CVE-2013-5166",
    "CVE-2013-5167",
    "CVE-2013-5168",
    "CVE-2013-5169",
    "CVE-2013-5170",
    "CVE-2013-5171",
    "CVE-2013-5172",
    "CVE-2013-5173",
    "CVE-2013-5174",
    "CVE-2013-5175",
    "CVE-2013-5176",
    "CVE-2013-5177",
    "CVE-2013-5178",
    "CVE-2013-5179",
    "CVE-2013-5180",
    "CVE-2013-5181",
    "CVE-2013-5182",
    "CVE-2013-5183",
    "CVE-2013-5184",
    "CVE-2013-5185",
    "CVE-2013-5186",
    "CVE-2013-5187",
    "CVE-2013-5188",
    "CVE-2013-5189",
    "CVE-2013-5190",
    "CVE-2013-5191",
    "CVE-2013-5192",
    "CVE-2013-5229"
  );
  script_bugtraq_id(
    49778,
    51239,
    51996,
    52379,
    52732,
    57842,
    58311,
    59058,
    60437,
    60444,
    60843,
    62520,
    62522,
    62523,
    62529,
    62531,
    62536,
    63284,
    63290,
    63311,
    63312,
    63313,
    63314,
    63316,
    63317,
    63319,
    63320,
    63321,
    63322,
    63329,
    63330,
    63331,
    63332,
    63335,
    63336,
    63339,
    63343,
    63344,
    63345,
    63346,
    63347,
    63348,
    63349,
    63350,
    63351,
    63352,
    63353
  );
  script_osvdb_id(
    74829,
    76326,
    79249,
    80009,
    80892,
    82462,
    89988,
    90892,
    92316,
    93959,
    93963,
    94628,
    97434,
    97435,
    97437,
    97438,
    97439,
    97440,
    98845,
    98846,
    98847,
    98848,
    98849,
    98850,
    98851,
    98852,
    98853,
    98854,
    98855,
    98856,
    98857,
    98858,
    98859,
    98860,
    98861,
    98862,
    98863,
    98864,
    98865,
    98866,
    98867,
    98868,
    98869,
    98870,
    98871,
    98872,
    98873,
    130246
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2013-10-22-3");
  script_xref(name:"CERT", value:"864643");

  script_name(english:"Mac OS X 10.x < 10.9 Multiple Vulnerabilities (BEAST)");
  script_summary(english:"Check the version of Mac OS X.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host is missing a Mac OS X update that fixes multiple
security vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running a version of Mac OS X 10.x that is prior
to version 10.9. The newer version contains multiple security-related
fixes for the following components :

  - Application Firewall
  - App Sandbox
  - Bluetooth
  - CFNetwork
  - CFNetwork SSL
  - Console
  - CoreGraphics
  - curl
  - dyld
  - IOKitUser
  - IOSerialFamily
  - Kernel
  - Kext Management
  - LaunchServices
  - Libc
  - Mail Accounts
  - Mail Header Display
  - Mail Networking
  - OpenLDAP
  - perl
  - Power Management
  - python
  - ruby
  - Security
  - Security - Authorization
  - Security - Smart Card Services
  - Screen Lock
  - Screen Sharing Server
  - syslog
  - USB"
  );
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT6011");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2013/Oct/msg00004.html");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2011/09/23/chromeandbeast.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/~bodo/tls-cbc.txt");
  script_set_attribute(attribute:"solution", value:"Upgrade to Mac OS X 10.9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/08/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/23");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

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

match = eregmatch(pattern:"Mac OS X (10\.[0-9.]+)", string:os);
if (!isnull(match))
{
  version = match[1];
  fixed_version = "10.9";

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
}

exit(0, "The host is not affected as it is running "+os+".");
