#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84400);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/09/12 13:45:32 $");

  script_cve_id(
    "CVE-2015-0286",
    "CVE-2015-0287",
    "CVE-2015-0288",
    "CVE-2015-0289",
    "CVE-2015-0292",
    "CVE-2015-0293"
  );
  script_bugtraq_id(
    73225,
    73227,
    73228,
    73231,
    73232,
    73237
  );
  script_osvdb_id(
    119328,
    119743,
    119755,
    119756,
    119757,
    119761
  );

  script_name(english:"Blue Coat ProxySG 6.2.x < 6.2.16.4 / 6.5.x < 6.5.7.5 / 6.6.x < 6.6.2.1 Multiple OpenSSL Vulnerabilities");
  script_summary(english:"Checks the Blue Coat ProxySG SGOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The self-reported SGOS version of the remote Blue Coat ProxySG device
is 6.2.x prior to 6.2.16.4, 6.5.x prior to 6.5.7.5, or 6.6.x prior to
6.6.2.1. Therefore, it contains a bundled version of OpenSSL that is
affected by multiple vulnerabilities :

  - An invalid read flaw exists in the ASN1_TYPE_cmp()
    function due to improperly performed boolean-type
    comparisons. A remote attacker can exploit this, via a
    crafted X.509 certificate sent to an endpoint that uses
    the certificate-verification feature, to cause an
    invalid read operation, resulting in a denial of
    service. (CVE-2015-0286)

  - A flaw exists in the ASN1_item_ex_d2i() function due to
    a failure to reinitialize 'CHOICE' and 'ADB' data
    structures when reusing a structure in ASN.1 parsing.
    This allows a remote attacker to cause an invalid write
    operation and memory corruption, resulting in a denial
    of service. (CVE-2015-0287)

  - A NULL pointer dereference flaw exists in the
    X509_to_X509_REQ() function due to improper processing
    of certificate keys. This allows a remote attacker, via
    a crafted X.509 certificate, to cause a denial of
    service. (CVE-2015-0288)

  - A NULL pointer dereference flaw exists in the PKCS#7
    parsing code due to incorrect handling of missing outer
    ContentInfo. This allows a remote attacker, using an
    application that processes arbitrary PKCS#7 data and
    providing malformed data with ASN.1 encoding, to cause
    a denial of service. (CVE-2015-0289)

  - An integer underflow condition exists in the
    EVP_DecodeUpdate() function due to improper validation
    of base64 encoded input when decoding. This allows a
    remote attacker, using maliciously crafted base64 data,
    to cause a segmentation fault or memory corruption,
    resulting in a denial of service or possibly the
    execution of arbitrary code. (CVE-2015-0292)

  - A flaw exists in servers that both support SSLv2 and
    enable export cipher suites due to improper
    implementation of SSLv2. A remote attacker can exploit
    this, via a crafted CLIENT-MASTER-KEY message, to cause
    a denial of service. (CVE-2015-0293)");
  script_set_attribute(attribute:"see_also",value:"https://bto.bluecoat.com/security-advisory/sa92");
  script_set_attribute(attribute:"solution",value:
"Upgrade to SGOS version 6.2.16.4 / 6.5.7.5 / 6.6.2.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date",value:"2014/05/06");
  script_set_attribute(attribute:"patch_publication_date",value:"2015/03/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/25");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/o:bluecoat:sgos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("bluecoat_proxy_sg_version.nasl");
  script_require_keys("Host/BlueCoat/ProxySG/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version    = get_kb_item_or_exit("Host/BlueCoat/ProxySG/Version");
ui_version = get_kb_item("Host/BlueCoat/ProxySG/UI_Version");

if(version !~ "^6\.([652])\.")
  audit(AUDIT_HOST_NOT, "Blue Coat ProxySG 6.6.x / 6.5.x / 6.2.x");

report_fix = NULL;

# Select version for report
if (isnull(ui_version)) report_ver = version;
else report_ver = ui_version;

if(version =~ "^6\.6\." && ver_compare(ver:version, fix:"6.6.2.1", strict:FALSE) == -1)
{
  fix    = '6.6.2.1';
  ui_fix = '6.6.2.1 Build 0';
}
else if(version =~ "^6\.5\." && ver_compare(ver:version, fix:"6.5.7.5", strict:FALSE) == -1)
{
  fix    = '6.5.7.5';
  ui_fix = '6.5.7.5 Build 0';
}
else if(version =~ "^6\.2\." && ver_compare(ver:version,fix:"6.2.16.4",strict:FALSE) == -1)
{
  fix    = '6.2.16.4';
  ui_fix = '6.2.16.4 Build 0';
}
else
  audit(AUDIT_INST_VER_NOT_VULN, 'Blue Coat ProxySG', version);

# Select fixed version for report
if (isnull(ui_version)) report_fix = fix;
else report_fix = ui_fix;

report =
  '\n  Installed version : ' + report_ver +
  '\n  Fixed version     : ' + report_fix +
  '\n';

security_report_v4(port:0, severity:SECURITY_HOLE, extra:report);
