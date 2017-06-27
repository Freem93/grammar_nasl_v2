#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92543);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/08/08 14:39:33 $");

  script_cve_id(
    "CVE-2013-2064",
    "CVE-2015-3193",
    "CVE-2015-3194",
    "CVE-2016-0702",
    "CVE-2016-0797",
    "CVE-2016-0799",
    "CVE-2016-2105",
    "CVE-2016-2107",
    "CVE-2016-3613"
  );
  script_bugtraq_id(
    60148,
    78623,
    83755,
    83763,
    89757,
    89760,
    91856
  );
  script_osvdb_id(
    93664,
    131037,
    131038,
    135096,
    135121,
    135151,
    137896,
    137899,
    141837
  );
  script_xref(name:"EDB-ID", value:"39768");

  script_name(english:"Oracle Secure Global Desktop Multiple Vulnerabilities (July 2016 CPU)");
  script_summary(english:"Checks the version of Oracle Secure Global Desktop.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Secure Global Desktop installed on the remote
host is 4.63, 4.71, or 5.2 and is missing a security patch from the
July 2016 Critical Patch Update (CPU). It is, therefore, affected by
the following vulnerabilities :

  - An integer overflow condition exists in the X Server
    subcomponent in the read_packet() function due to
    improper validation of user-supplied input when
    calculating the amount of memory required to handle
    returned data. A remote attacker can exploit this to
    cause a denial of service condition or the execution of
    arbitrary code. Note that this vulnerability only
    affects versions 4.71 and 5.2. (CVE-2013-2064)

  - A carry propagating flaw exists in the OpenSSL
    subcomponent in the x86_64 Montgomery squaring
    implementation that may cause the BN_mod_exp() function
    to produce incorrect results. An attacker can exploit
    this to obtain sensitive information regarding private
    keys. (CVE-2015-3193)

  - A NULL pointer dereference flaw exists in the OpenSSL
    subcomponent in file rsa_ameth.c when handling ASN.1
    signatures that use the RSA PSS algorithm but are
    missing a mask generation function parameter. A remote
    attacker can exploit this to cause the signature
    verification routine to crash, leading to a denial of
    service. (CVE-2015-3194)

  - A key disclosure vulnerability exists in the OpenSSL
    subcomponent due to improper handling of cache-bank
    conflicts on the Intel Sandy-bridge microarchitecture.
    An attacker can exploit this to gain access to RSA key
    information. (CVE-2016-0702)

  - A NULL pointer dereference flaw exists in the OpenSSL
    subcomponent in the BN_hex2bn() and BN_dec2bn()
    functions. A remote attacker can exploit this to trigger
    a heap corruption, resulting in the execution of
    arbitrary code. (CVE-2016-0797)

  - Multiple memory corruption issues exist in the OpenSSL
    subcomponent that allow a remote attacker to cause a
    denial of service condition or the execution of
    arbitrary code. (CVE-2016-0799)

  - A heap buffer overflow condition exists in the OpenSSL
    subcomponent in the EVP_EncodeUpdate() function within
    file crypto/evp/encode.c that is triggered when handling
    a large amount of input data. An unauthenticated, remote
    attacker can exploit this to cause a denial of service
    condition. (CVE-2016-2105)

  - Multiple flaws exist in the OpenSSL subcomponent in the
    aesni_cbc_hmac_sha1_cipher() function in file
    crypto/evp/e_aes_cbc_hmac_sha1.c and the
    aesni_cbc_hmac_sha256_cipher() function in file
    crypto/evp/e_aes_cbc_hmac_sha256.c that are triggered
    when the connection uses an AES-CBC cipher and AES-NI
    is supported by the server. A man-in-the-middle attacker
    can exploit these to conduct a padding oracle attack,
    resulting in the ability to decrypt the network traffic.
    (CVE-2016-2107)

  - An unspecified flaw exists in the OpenSSL subcomponent
    that allows a remote attacker to execute arbitrary
    code. (CVE-2016-3613)");
  # http://www.oracle.com/technetwork/security-advisory/cpujul2016-2881720.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?453b5f8c");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2016 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/05/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:virtualization_secure_global_desktop");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("oracle_secure_global_desktop_installed.nbin");
  script_require_keys("Host/Oracle_Secure_Global_Desktop/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app = "Oracle Secure Global Desktop";
version = get_kb_item_or_exit("Host/Oracle_Secure_Global_Desktop/Version");

# this check is for Oracle Secure Global Desktop packages built for Linux platform
uname = get_kb_item_or_exit("Host/uname");
if ("Linux" >!< uname) audit(AUDIT_OS_NOT, "Linux");

fix_required = NULL;

if (version =~ "^5\.20($|\.)") fix_required = 'Patch_52p6';
else if (version =~ "^4\.71($|\.)") fix_required = 'Patch_471p9';
else if (version =~ "^4\.63($|\.)") fix_required = 'Patch_463p9';

if (isnull(fix_required)) audit(AUDIT_INST_VER_NOT_VULN, "Oracle Secure Global Desktop", version);

patches = get_kb_list("Host/Oracle_Secure_Global_Desktop/Patches");

patched = FALSE;
foreach patch (patches)
{
  if (patch == fix_required)
  {
    patched = TRUE;
    break;
  }
}

if (patched) audit(AUDIT_INST_VER_NOT_VULN, app, version + ' (with ' + fix_required + ')');

report = '\n  Installed version : ' + version +
           '\n  Patch required    : ' + fix_required +
           '\n';
security_report_v4(port:0, extra:report, severity:SECURITY_HOLE);
