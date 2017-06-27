#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91814);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/03/07 17:25:25 $");

  script_cve_id(
    "CVE-2016-3074",
    "CVE-2016-4537",
    "CVE-2016-4538",
    "CVE-2016-4539",
    "CVE-2016-4540",
    "CVE-2016-4541",
    "CVE-2016-4542",
    "CVE-2016-4543",
    "CVE-2016-4544"
  );
  script_bugtraq_id(
    87087,
    89844,
    90172,
    90173,
    90174
  );
  script_osvdb_id(
    137447,
    137781,
    137782,
    137783,
    137784
  );

  script_name(english:"Tenable SecurityCenter < 5.3.2 Multiple Vulnerabilities (TNS-2016-09)");
  script_summary(english:"Checks the version of PHP in SecurityCenter.");

  script_set_attribute(attribute:"synopsis", value:
"The Tenable SecurityCenter application installed on the remote host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Tenable SecurityCenter application installed on the remote host is
either prior to version 5.3.2 or is missing a security patch. It is,
therefore, affected by multiple vulnerabilities in the bundled version
of PHP :

  - A signedness error exists in the GD Graphics library in
    gd_gd2.c due to improper validation of user-supplied
    input when handling compressed GD2 data. An
    unauthenticated, remote attacker can exploit this to
    cause a heap-based buffer overflow, resulting in a
    denial of service condition or the execution of
    arbitrary code. (CVE-2016-3074)

  - An out-of-bounds read error exists in the php_str2num()
    function in bcmath.c when handling negative scales. An
    unauthenticated, remote attacker can exploit this, via a
    crafted call, to cause a denial of service condition or
    the disclosure of memory contents. (CVE-2016-4537)

  - A flaw exists in the bcpowmod() function in bcmath.c due
    to modifying certain data structures without considering
    whether they are copies of the _zero_, _one_, or _two_
    global variables. An unauthenticated, remote attacker
    can exploit this, via a crafted call, to cause a denial
    of service condition. (CVE-2016-4538)

  - A flaw exists in the xml_parse_into_struct() function in
    xml.c when handling specially crafted XML contents. An
    unauthenticated, remote attacker can exploit this to
    cause a denial of service condition. (CVE-2016-4539)

  - Multiple out-of-bounds read errors exist within file
    ext/intl/grapheme/grapheme_string.c when handling
    negative offsets in the zif_grapheme_stripos() and
    zif_grapheme_strpos() functions. An unauthenticated,
    remote attacker can exploit these issues to cause a
    denial of service condition or disclose memory contents.
    (CVE-2016-4540, CVE-2016-4541)

  - A flaw exists in the exif_process_IFD_TAG() function in
    exif.c due to improper construction of spprintf
    arguments. An unauthenticated, remote attacker can
    exploit this, via crafted header data, to cause an
    out-of-bounds read error, resulting in a denial of
    service condition or the disclosure of memory contents.
    (CVE-2016-4542)

  - A flaw exists in the exif_process_IFD_in_JPEG() function
    in exif.c due to improper validation of IFD sizes. An
    unauthenticated, remote attacker can exploit this, via
    crafted header data, to cause an out-of-bounds read
    error, resulting in a denial of service condition or the
    disclosure of memory contents. (CVE-2016-4543)

  - A flaw exists in the exif_process_TIFF_in_JPEG()
    function in exif.c due to improper validation of TIFF
    start data. An unauthenticated, remote attacker can
    exploit this, via crafted header data, to cause an
    out-of-bounds read error, resulting in a denial of
    service condition or the disclosure of memory contents.
    (CVE-2016-4544)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2016-09");
  script_set_attribute(attribute:"see_also", value:"http://php.net/ChangeLog-5.php#5.6.21");
  script_set_attribute(attribute:"solution", value:
"Upgrade to SecurityCenter version 5.3.2 or later. Alternatively, apply
the relevant patch as referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:securitycenter");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("securitycenter_installed.nbin");
  script_require_keys("Host/local_checks_enabled","Host/SecurityCenter/Version","Host/SecurityCenter/support/php/version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

appname = 'SecurityCenter';

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
sc_ver = get_kb_item_or_exit("Host/SecurityCenter/Version");
# Affected: SecurityCenter 4.8.2, 5.0.2, 5.1.0, 5.2.0, 5.3.1
if (sc_ver !~ "^(4\.8\.2($|\.)|5\.0\.2($|\.)|5\.1\.0($|\.)|5\.2\.0($|\.)|5\.3\.1($|\.))") 
  audit(AUDIT_INST_VER_NOT_VULN, "SecurityCenter", sc_ver);

# Grab php version from kb
version = get_kb_item("Host/SecurityCenter/support/php/version");

if (empty_or_null(version)) audit(AUDIT_UNKNOWN_APP_VER, "PHP bundled with Tenable SecurityCenter");

fix = "5.6.21"; # default to known php release branch used in advisory
if (version =~ "^5\.4\.") fix = "5.4.45";
if (version =~ "^7\.0\.") fix = "7.0.6";

if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  report = '\n' +
    '\n  SecurityCenter version     : ' + sc_ver +
    '\n  SecurityCenter PHP version : ' + version +
    '\n  Fixed PHP version          : ' + fix +
    '\n';
  security_report_v4(port:0, severity:SECURITY_HOLE, extra:report);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "PHP (within SecurityCenter)", version);
