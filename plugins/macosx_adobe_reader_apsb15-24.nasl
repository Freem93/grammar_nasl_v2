#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86405);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/04/28 18:42:40 $");

  script_cve_id(
    "CVE-2015-5583",
    "CVE-2015-5586",
    "CVE-2015-6683",
    "CVE-2015-6684",
    "CVE-2015-6685",
    "CVE-2015-6686",
    "CVE-2015-6687",
    "CVE-2015-6688",
    "CVE-2015-6689",
    "CVE-2015-6690",
    "CVE-2015-6691",
    "CVE-2015-6692",
    "CVE-2015-6693",
    "CVE-2015-6694",
    "CVE-2015-6695",
    "CVE-2015-6696",
    "CVE-2015-6697",
    "CVE-2015-6698",
    "CVE-2015-6699",
    "CVE-2015-6700",
    "CVE-2015-6701",
    "CVE-2015-6702",
    "CVE-2015-6703",
    "CVE-2015-6704",
    "CVE-2015-6705",
    "CVE-2015-6706",
    "CVE-2015-6707",
    "CVE-2015-6708",
    "CVE-2015-6709",
    "CVE-2015-6710",
    "CVE-2015-6711",
    "CVE-2015-6712",
    "CVE-2015-6713",
    "CVE-2015-6714",
    "CVE-2015-6715",
    "CVE-2015-6716",
    "CVE-2015-6717",
    "CVE-2015-6718",
    "CVE-2015-6719",
    "CVE-2015-6720",
    "CVE-2015-6721",
    "CVE-2015-6722",
    "CVE-2015-6723",
    "CVE-2015-6724",
    "CVE-2015-6725",
    "CVE-2015-7614",
    "CVE-2015-7615",
    "CVE-2015-7616",
    "CVE-2015-7617",
    "CVE-2015-7618",
    "CVE-2015-7619",
    "CVE-2015-7620",
    "CVE-2015-7621",
    "CVE-2015-7622",
    "CVE-2015-7623",
    "CVE-2015-7624",
    "CVE-2015-7650",
    "CVE-2015-8458"
  );
  script_bugtraq_id(
    77064,
    77066,
    77067,
    77068,
    77069,
    77070,
    77074,
    79208
  );
  script_osvdb_id(
    128706,
    128707,
    128708,
    128709,
    128710,
    128711,
    128712,
    128713,
    128714,
    128715,
    128716,
    128717,
    128718,
    128719,
    128720,
    128721,
    128722,
    128723,
    128724,
    128725,
    128726,
    128727,
    128728,
    128729,
    128730,
    128731,
    128732,
    128733,
    128734,
    128735,
    128736,
    128737,
    128738,
    128739,
    128740,
    128741,
    128742,
    128743,
    128744,
    128745,
    128746,
    128747,
    128748,
    128749,
    128750,
    128751,
    128752,
    128753,
    128754,
    128755,
    128756,
    128757,
    128758,
    128759,
    128760,
    128761,
    129615,
    131708
  );

  script_name(english:"Adobe Reader <= 10.1.15 / 11.0.12 / 2015.006.30060 / 2015.008.20082 Multiple Vulnerabilities (APSB15-24) (Mac OS X)");
  script_summary(english:"Checks the version of Adobe Reader.");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Reader installed on the remote Mac OS X host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Reader installed on the remote Mac OS X host is
version 10.1.15 / 11.0.12 / 2015.006.30060 / 2015.008.20082 or
earlier. It is, therefore, affected by multiple vulnerabilities :

  - A buffer overflow condition exists that allows an
    attacker to disclose information. (CVE-2015-6692)

  - Multiple use-after-free errors exist that allow an
    attacker to execute arbitrary code. (CVE-2015-6689,
    CVE-2015-6688, CVE-2015-6690, CVE-2015-7615,
    CVE-2015-7617, CVE-2015-6687, CVE-2015-6684,
    CVE-2015-6691, CVE-2015-7621, CVE-2015-5586,
    CVE-2015-6683)

  - Multiple heap buffer overflow conditions exist that
    allow an attacker to execute arbitrary code.
    (CVE-2015-6696, CVE-2015-6698, CVE-2015-8458)

  - Multiple memory corruption issues exist that allow a
    remote attacker to execute arbitrary code.
    (CVE-2015-6685, CVE-2015-6693, CVE-2015-6694,
    CVE-2015-6695, CVE-2015-6686, CVE-2015-7622,
    CVE-2015-7650)

  - Multiple unspecified memory leak vulnerabilities exist.
    (CVE-2015-6699, CVE-2015-6700, CVE-2015-6701,
    CVE-2015-6702, CVE-2015-6703, CVE-2015-6704,
    CVE-2015-6697)

  - Multiple security bypass vulnerabilities exist that
    allow a remote attacker to disclose information.
    (CVE-2015-5583, CVE-2015-6705, CVE-2015-6706,
    CVE-2015-7624)

  - Multiple security bypass vulnerabilities exists that
    allow an attacker to bypass JavaScript API execution.
    (CVE-2015-6707, CVE-2015-6708, CVE-2015-6709,
    CVE-2015-6710, CVE-2015-6711, CVE-2015-6712,
    CVE-2015-7614, CVE-2015-7616, CVE-2015-6716,
    CVE-2015-6717, CVE-2015-6718, CVE-2015-6719,
    CVE-2015-6720, CVE-2015-6721, CVE-2015-6722,
    CVE-2015-6723, CVE-2015-6724, CVE-2015-6725,
    CVE-2015-7618, CVE-2015-7619, CVE-2015-7620,
    CVE-2015-7623, CVE-2015-6713, CVE-2015-6714,
    CVE-2015-6715)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/acrobat/apsb15-24.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Reader 10.1.16 / 11.0.13 / 2015.006.30094 / 
2015.009.20069 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat_reader");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_adobe_reader_installed.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/Adobe Reader");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

get_kb_item_or_exit("Host/local_checks_enabled");
os = get_kb_item("Host/MacOSX/Version");
if (empty_or_null(os)) audit(AUDIT_OS_NOT, "Mac OS X");

app_name = "Adobe Reader";
install = get_single_install(app_name:app_name);

version = install['version'];
path    = install['path'];

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

# Affected is :
#
# 10.x <= 10.1.15
# 11.x <= 11.0.12
# DC Classic <= 2015.006.30060
# DC Continuous <= 2015.008.20082
if (
  (ver[0] == 10 && ver[1] < 1) ||
  (ver[0] == 10 && ver[1] == 1 && ver[2] <= 15) ||
  (ver[0] == 11 && ver[1] == 0 && ver[2] <= 12) ||
  (ver[0] == 15 && ver[1] == 6 && ver[2] <= 30060) ||
  (ver[0] == 15 && ver[1] == 7 ) ||
  (ver[0] == 15 && ver[1] == 8 && ver[2] <= 20082)
)
{
  if (report_verbosity > 0)
  {
    report = '\n  Path              : '+path+
             '\n  Installed version : '+version+
             '\n  Fixed version     : 10.1.16 / 11.0.13 / 2015.006.30094 / 2015.009.20069' +
             '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);
