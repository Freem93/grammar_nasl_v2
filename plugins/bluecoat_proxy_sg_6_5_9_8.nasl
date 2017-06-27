#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93381);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/11/11 20:08:42 $");

  script_cve_id(
    "CVE-2016-2107",
    "CVE-2016-2108",
    "CVE-2016-2109"
  );
  script_bugtraq_id(
    87940,
    89752,
    89760
  );
  script_osvdb_id(
    137577,
    137896,
    137900
  );
  script_xref(name:"EDB-ID", value:"39768");
  script_xref(name:"IAVA", value:"2016-A-0230");

  script_name(english:"Blue Coat ProxySG 6.5.x < 6.5.9.8 / 6.6.x < 6.6.4.1 Multiple OpenSSL Vulnerabilities");
  script_summary(english:"Checks the Blue Coat ProxySG SGOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The self-reported SGOS version installed on the remote Blue Coat
ProxySG device is 6.5.x prior to 6.5.9.8 or 6.6.x prior to 6.6.4.1. It
is, therefore, affected by multiple vulnerabilities in its bundled
version of OpenSSL :

  - Multiple flaws exist in the aesni_cbc_hmac_sha1_cipher()
    function in file crypto/evp/e_aes_cbc_hmac_sha1.c and
    the aesni_cbc_hmac_sha256_cipher() function in file
    crypto/evp/e_aes_cbc_hmac_sha256.c that are triggered
    when the connection uses an AES-CBC cipher and AES-NI
    is supported by the server. A man-in-the-middle attacker
    can exploit these to conduct a padding oracle attack,
    resulting in the ability to decrypt the network traffic.
    Note that this issue does not affect the SG300 and SG600
    hardware platforms. (CVE-2016-2107)

  - A remote code execution vulnerability exists in the
    ASN.1 encoder due to an underflow condition that occurs
    when attempting to encode the value zero represented as
    a negative integer. An unauthenticated, remote attacker
    can exploit this to corrupt memory, resulting in the
    execution of arbitrary code. (CVE-2016-2108)

  - Multiple unspecified flaws exist in the d2i BIO
    functions when reading ASN.1 data from a BIO due to
    invalid encoding causing a large allocation of memory.
    An unauthenticated, remote attacker can exploit these to
    cause a denial of service condition through resource
    exhaustion. Note that this issue only affects management
    connections. (CVE-2016-2109)");
  script_set_attribute(attribute:"see_also",value:"https://bto.bluecoat.com/security-advisory/sa123");
  script_set_attribute(attribute:"solution",value:
"Upgrade to Blue Coat SGOS version 6.5.9.8 / 6.6.4.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date",value:"2016/04/22");
  script_set_attribute(attribute:"patch_publication_date",value:"2016/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/08");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/o:bluecoat:sgos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("bluecoat_proxy_sg_version.nasl");
  script_require_keys("Host/BlueCoat/ProxySG/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version    = get_kb_item_or_exit("Host/BlueCoat/ProxySG/Version");
ui_version = get_kb_item("Host/BlueCoat/ProxySG/UI_Version");

if(version !~ "^6\.([65])\.")
  audit(AUDIT_HOST_NOT, "Blue Coat ProxySG 6.6.x / 6.5.x");

report_fix = NULL;

# Select version for report
if (isnull(ui_version)) report_ver = version;
else report_ver = ui_version;

if(version =~ "^6\.6\." && ver_compare(ver:version, fix:"6.6.4.1", strict:FALSE) == -1)
{
  fix    = '6.6.4.1';
  ui_fix = '6.6.4.1 Build 0';
}
else if(version =~ "^6\.5\." && ver_compare(ver:version, fix:"6.5.9.8", strict:FALSE) == -1)
{
  fix    = '6.5.9.8';
  ui_fix = '6.5.9.8 Build 0';
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
