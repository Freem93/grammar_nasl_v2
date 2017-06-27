#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96453);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/05/05 19:22:14 $");

  script_cve_id(
    "CVE-2017-2939",
    "CVE-2017-2940",
    "CVE-2017-2941",
    "CVE-2017-2942",
    "CVE-2017-2943",
    "CVE-2017-2944",
    "CVE-2017-2945",
    "CVE-2017-2946",
    "CVE-2017-2947",
    "CVE-2017-2948",
    "CVE-2017-2949",
    "CVE-2017-2950",
    "CVE-2017-2951",
    "CVE-2017-2952",
    "CVE-2017-2953",
    "CVE-2017-2954",
    "CVE-2017-2955",
    "CVE-2017-2956",
    "CVE-2017-2957",
    "CVE-2017-2958",
    "CVE-2017-2959",
    "CVE-2017-2960",
    "CVE-2017-2961",
    "CVE-2017-2962",
    "CVE-2017-2963",
    "CVE-2017-2964",
    "CVE-2017-2965",
    "CVE-2017-2966",
    "CVE-2017-2967",
    "CVE-2017-3009",
    "CVE-2017-3010"
  );
  script_bugtraq_id(
    95340,
    95343,
    95344,
    95345,
    95346,
    95348,
    97302,
    97306
  );
  script_osvdb_id(
    149854,
    149855,
    149856,
    149857,
    149858,
    149859,
    149860,
    149861,
    149862,
    149863,
    149864,
    149865,
    149866,
    149867,
    149868,
    149869,
    149870,
    149871,
    149872,
    149873,
    149874,
    149875,
    149876,
    149877,
    149878,
    149879,
    149880,
    149881,
    149882,
    154712,
    154713
  );

  script_name(english:"Adobe Reader < 11.0.19 / 15.006.30279 / 15.023.20053 Multiple Vulnerabilities (APSB17-01)");
  script_summary(english:"Checks the version of Adobe Reader.");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Reader installed on the remote Windows host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Reader installed on the remote Windows host is
prior to 11.0.19, 15.006.30279, or 15.023.20053. It is, therefore,
affected by multiple vulnerabilities :

  - Multiple memory corruption issues exist due to improper
    validation of unspecified input. An unauthenticated,
    remote attacker can exploit these to execute arbitrary
    code. (CVE-2017-2939, CVE-2017-2940, CVE-2017-2941,
    CVE-2017-2943, CVE-2017-2944, CVE-2017-2953,
    CVE-2017-2954)

  - Multiple heap buffer overflow conditions exist due to
    improper validation of unspecified input. An
    unauthenticated, remote attacker can exploit these to
    execute arbitrary code. (CVE-2017-2942, CVE-2017-2945,
    CVE-2017-2959)

  - A heap buffer overflow condition exists when handling
    JPEG2000 images due to improper validation of
    unspecified input. An unauthenticated, remote attacker
    can exploit this to execute arbitrary code.
    (CVE-2017-2946)

  - An unspecified security bypass vulnerability exists that
    allows an unauthenticated, remote attacker to have an
    unspecified impact. (CVE-2017-2947)

  - Multiple overflow conditions exist due to improper
    validation of unspecified input. An unauthenticated,
    remote attacker can exploit these to execute arbitrary
    code. (CVE-2017-2948, CVE-2017-2952)

  - A heap buffer overflow condition exists when handling
    the XSLT element-available() function that allows an
    unauthenticated, remote attacker to execute arbitrary
    code. (CVE-2017-2949)

  - Multiple use-after-free memory errors exist when handling
    XFA subform layouts, hyphenation objects, field font
    sizes, and template objects. An unauthenticated, remote
    attacker can exploit these to execute arbitrary code.
    (CVE-2017-2950, CVE-2017-2951, CVE-2017-2961,
    CVE-2017-2967)

  - Multiple use-after-free memory errors exist that allow
    an unauthenticated, remote attacker to execute arbitrary
    code. (CVE-2017-2955, CVE-2017-2956, CVE-2017-2957,
    CVE-2017-2958)

  - Multiple memory corruption issues exist when handling
    JPEG and TIFF files due to improper validation of
    unspecified input. An unauthenticated, remote attacker
    can exploit these to execute arbitrary code.
    (CVE-2017-2960, CVE-2017-2963, CVE-2017-2964,
    CVE-2017-2965)

  - A type confusion error exists when handling the XSLT
    lang() function that allows an unauthenticated, remote
    attacker to execute arbitrary code. (CVE-2017-2962)

  - A heap buffer overflow condition exists in the
    ImageConversion component when handling TIFF images()
    due to improper validation of unspecified input. An
    unauthenticated, remote attacker can exploit this to
    execute arbitrary code. (CVE-2017-2966)

  - A buffer overflow condition exists in the JPEG2000
    parser due to improper validation of unspecified input.
    An unauthenticated, remote attacker can exploit this to
    disclose sensitive information. (CVE-2017-3009)

  - A memory corruption issue exists in the Rendering engine
    due to improper validation of unspecified input. An
    unauthenticated, remote attacker can exploit this to
    cause a denial of service condition or the execution of
    arbitrary code. (CVE-2017-3010)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/acrobat/apsb17-01.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Reader version 11.0.19 / 15.006.30279 / 15.023.20053
or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat_reader");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("adobe_reader_installed.nasl");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/Adobe Reader");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

app_name = "Adobe Reader";
install = get_single_install(app_name:app_name);

version = install['version'];
path    = install['path'];
verui   = install['display_version'];

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

# Affected is :
#
# 11.x < 11.0.19
# DC Classic < 15.006.30279
# DC Continuous < 15.023.20053
if (
  (ver[0] == 11 && ver[1] == 0 && ver[2] <= 18) ||
  (ver[0] == 15 && ver[1] == 6 && ver[2] <= 30244) ||
  (ver[0] == 15 && ver[1] >= 7 && ver[1] <= 19) ||
  (ver[0] == 15 && ver[1] == 20 && ver[2] <= 20042)
)
{
  port = get_kb_item('SMB/transport');
  if(!port) port = 445;

  report = '\n  Path              : '+path+
           '\n  Installed version : '+verui+
           '\n  Fixed version     : 11.0.19 / 15.006.30279 / 15.023.20053' +
           '\n';
  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, verui, path);
