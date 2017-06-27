#TRUSTED aa44a4996afe74cf24ceee34cba1f1742ded09dd5d80aadd3f77e69cde93f796c6429ea020ecbfeeefb0b37d87ebf9b5b644e3894bf8c19e169c3662c7eeee823655d4ec98798599d73b223d8dfcb60e0c24f11863d3ae9800512656b8693df1e821764a8b21c4f3142bfb9f4062913fff106fe177fef065cf17d27b2eaf6e95a4bf51af8c594c8230abf61aacd63ebaf5e140647c0325d6a9f2b8bf3a7ad07440f5626ae894eabcb2575f126c809b8340ac8d4a2ffb288ff8248de738133ab8ce28d8a8522d729e49b662f995e99d1ea788484cfdd96731baec09f4a85efa6f1e032432c60662440cc5d637acef1a38e618ddec3cd791e74e17c19a8162e7d3a0b9ef4ed38e8e36a2c631127aecf56fdf8ab3fe9af8cc2a39ee8088c6291f88c4c5caef2c98b3cfca78a625e59dbab8150041145be30dd393f64fe8272d1c1ed06f36b808aa7c0aec659ea7b2623b88c955e86298369bd8236e2eabde1d4fe34b138837e8b9a3ca685002d3a11ec7638bbcc5c58161e404e9e1a722599a5ab902e804e8c00ac6fa143a5593568890ba0bfdf83ed10b754dc782676bb978a0689a86f5a9431aa4ddf605a210bdc62112f9b70938fd45c1c4062705cf9576a730da1754fa63ec8c42a4019f82c41af8390e70d6814335902f8edead0078a7990fd708fca8be2a17c97757da2a6f363fce83662c263f989b842043c82a3f82ceac
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81912);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2015/11/01");

  script_cve_id(
    "CVE-2014-9293",
    "CVE-2014-9294",
    "CVE-2014-9295",
    "CVE-2014-9296"
  );
  script_bugtraq_id(71757, 71758, 71761, 71762);
  script_osvdb_id(116066, 116067, 116068, 116069, 116070, 116074);
  script_xref(name:"CERT", value:"852879");
  script_xref(name:"CISCO-BUG-ID", value:"CSCus26956");

  script_name(english:"Cisco IOS XR Multiple ntpd Vulnerabilities");
  script_summary(english:"Checks the IOS XR version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco device is running a version of IOS XR software that
is affected by the following vulnerabilities :

  - Errors exist related to weak cryptographic pseudorandom
    number generation (PRNG), the functions 'ntp_random' and
    and 'config_auth', and the 'ntp-keygen' utility. A
    man-in-the-middle attacker can exploit these to disclose
    sensitive information. (CVE-2014-9293, CVE-2014-9294)

  - Multiple stack-based buffer overflow errors exist in the
    Network Time Protocol daemon (ntpd), which a remote
    attacker can exploit to execute arbitrary code or cause
    a denial of service by using a specially crafted packet.
    (CVE-2014-9295)

  - An error exists in the 'receive' function in the Network
    Time Protocol daemon (ntpd) that allows denial of
    service attacks. (CVE-2014-9296)");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20141222-ntpd
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?79cfbf7f");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/534319");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch or workaround referenced in Cisco bug ID
CSCus26956.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

version  = get_kb_item_or_exit("Host/Cisco/IOS-XR/Version");
override = FALSE;

# Check model
# per bug page :
# - "NCS6K, NCS4K,ASR9K, CRS, C12K"
model = get_kb_item("CISCO/model");
if (model)
{
  if (
    model !~ "^ciscoASR9[0-9]{3}"
    &&
    model !~ "^cisco([Nn]cs|NCS)(4016|4k|6008|6k)"
    &&
    model !~ "^ciscoCRS\d+(S|SB|B)"
  ) audit(AUDIT_HOST_NOT, "an affected model");
}
else
{
  model = get_kb_item_or_exit("Host/Cisco/IOS-XR/Model");
  if (
    "ASR9K"   >!< model
    &&
    "NCS6K"   >!< model
    &&
    "NCS6008" >!< model
    &&
    "NCS4016" >!< model
    &&
    "NCS4K"   >!< model
    &&
    "CRS-1"   >!< model
    &&
    "C12K"    >!< model
  ) audit(AUDIT_HOST_NOT, "an affected model");
}

# Check version
# per bug page :
#  - "CSCus26956 impacts all releases prior to XR 5.3.1."
if (
  !(
    version =~ "^[0-4]\."
    ||
    version =~ "^5\.[0-2]\."
    ||
    version =~ "5.3.0($|[^0-9])"
  )
) audit(AUDIT_INST_VER_NOT_VULN, 'Cisco IOS XR', version);

if (!isnull(get_kb_item("Host/local_checks_enabled")))
{
  buf = cisco_command_kb_item("Host/Cisco/Config/show_ntp_status", "show ntp status");
  # Check for traces of ntp
  if (check_cisco_result(buf))
  {
      if (
        "%NTP is not enabled." >< buf
        &&
        "system poll" >!< buf
        &&
        "Clock is" >!< buf
      ) audit(AUDIT_HOST_NOT, "affected because NTP is not enabled.");
  }
  else if (cisco_needs_enable(buf)) override = TRUE;
}

if (report_verbosity > 0)
{
  report =
    '\n  Cisco bug IDs     : CSCus26956' +
    '\n  Installed release : ' + version +
    '\n  Fixed release     : 5.3.1.18i.BASE' +
    '\n';
  security_hole(port:0, extra:report+cisco_caveat(override));
}
else security_hole(port:0, extra:cisco_caveat(override));
