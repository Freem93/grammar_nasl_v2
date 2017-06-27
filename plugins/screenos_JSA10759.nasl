#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94679);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/12/14 20:22:11 $");

  script_cve_id(
    "CVE-2016-0703",
    "CVE-2016-0704",
    "CVE-2016-0797",
    "CVE-2016-0800",
    "CVE-2016-2105",
    "CVE-2016-2106",
    "CVE-2016-2108"
  );
  script_bugtraq_id(
    83733,
    83743,
    83763,
    83764,
    89744,
    89752,
    89757
  );
  script_osvdb_id(
    135121,
    135149,
    135152,
    135153,
    137898,
    137899,
    137900
  );
  script_xref(name:"JSA", value:"JSA10759");
  script_xref(name:"CERT", value:"583776");

  script_name(english:"Juniper ScreenOS 6.3.x < 6.3.0r23 Multiple Vulnerabilities in OpenSSL (JSA10759) (DROWN)");
  script_summary(english:"Checks the version of ScreenOS.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Juniper ScreenOS running on the remote host is 6.3.x
prior to 6.3.0r23. It is, therefore, affected by multiple
vulnerabilities in its bundled version of OpenSSL :

  - A flaw exists in the SSLv2 implementation,
    specifically in the get_client_master_key() function
    within file s2_srvr.c, due to accepting a nonzero
    CLIENT-MASTER-KEY CLEAR-KEY-LENGTH value for an
    arbitrary cipher. A man-in-the-middle attacker can
    exploit this to determine the MASTER-KEY value and
    decrypt TLS ciphertext by leveraging a Bleichenbacher
    RSA padding oracle. (CVE-2016-0703)

  - A flaw exists in the SSLv2 oracle protection mechanism,
    specifically in the get_client_master_key() function
    within file s2_srvr.c, due to incorrectly overwriting
    MASTER-KEY bytes during use of export cipher suites.
    A remote attackers can exploit this to more easily
    decrypt TLS ciphertext by leveraging a Bleichenbacher
    RSA padding oracle. (CVE-2016-0704)

  - A NULL pointer dereference flaw exists in the
    BN_hex2bn() and BN_dec2bn() functions. A remote attacker
    can exploit this to trigger a heap corruption, resulting
    in the execution of arbitrary code. (CVE-2016-0797)

  - A flaw exists that allows a cross-protocol
    Bleichenbacher padding oracle attack known as DROWN
    (Decrypting RSA with Obsolete and Weakened eNcryption).
    This vulnerability exists due to a flaw in the Secure
    Sockets Layer Version 2 (SSLv2) implementation, and it
    allows captured TLS traffic to be decrypted. A
    man-in-the-middle attacker can exploit this to decrypt
    the TSL connection by utilizing previously captured
    traffic and weak cryptography along with a series of
    specially crafted connections to an SSLv2 server that
    uses the same private key. (CVE-2016-0800)

  - A heap buffer overflow condition exists in the
    EVP_EncodeUpdate() function within file
    crypto/evp/encode.c that is triggered when handling
    a large amount of input data. An unauthenticated, remote
    attacker can exploit this to cause a denial of service
    condition. (CVE-2016-2105)

  - A heap buffer overflow condition exists in the
    EVP_EncryptUpdate() function within file
    crypto/evp/evp_enc.c that is triggered when handling a
    large amount of input data after a previous call occurs
    to the same function with a partial block. An
    unauthenticated, remote attacker can exploit this to
    cause a denial of service condition. (CVE-2016-2106)

  - A remote code execution vulnerability exists in the
    ASN.1 encoder due to an underflow condition that occurs
    when attempting to encode the value zero represented as
    a negative integer. An unauthenticated, remote attacker
    can exploit this to corrupt memory, resulting in the
    execution of arbitrary code. (CVE-2016-2108)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10759");
  # http://www.juniper.net/techpubs/en_US/screenos6.3.0/information-products/pathway-pages/screenos/index.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c4eb1929");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20151203.txt");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20160301.txt");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20160503.txt");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20160922.txt");
  script_set_attribute(attribute:"see_also", value:"https://www.drownattack.com/drown-attack-paper.pdf");
  script_set_attribute(attribute:"see_also", value:"https://drownattack.com/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Juniper ScreenOS version 6.3.0r23 or later. Alternatively,
refer to the vendor advisory for additional workarounds.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:screenos");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("screenos_version.nbin", "screenos_unsupported.nasl");
  script_require_keys("Host/Juniper/ScreenOS/display_version", "Host/Juniper/ScreenOS/version");
  script_exclude_keys("Host/Juniper/ScreenOS/unsupported");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "Juniper ScreenOS";
display_version = get_kb_item_or_exit("Host/Juniper/ScreenOS/display_version");
version = get_kb_item_or_exit("Host/Juniper/ScreenOS/version");
if (get_kb_item("Host/Juniper/ScreenOS/unsupported"))
  exit(0, app_name + " version " + display_version + " is installed and no longer supported, therefore, it was not checked."); 

# prior to 6.3.0r23 are affected. 6.2 and prior are unsupported
# fix is 6.3.0r23 and later
if (ver_compare(ver:version, minver:"6.3.0.0", fix:"6.3.0.23", strict:FALSE) < 0)
{
  display_fix = "6.3.0r23";

  port = 0;
  report =
    '\n  Installed version : ' + display_version +
    '\n  Fixed version     : ' + display_fix +
    '\n';

  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, display_version);
