#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94963);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/02/06 16:27:35 $");

  script_cve_id(
    "CVE-2016-7053",
    "CVE-2016-7054",
    "CVE-2016-7055"
  );
  script_bugtraq_id(
    94238,
    94242,
    94244
  );
  script_osvdb_id(
    147019,
    147020,
    147021
  );

  script_name(english:"OpenSSL 1.1.0 < 1.1.0c Multiple Vulnerabilities");
  script_summary(english:"Performs a banner check.");

  script_set_attribute(attribute:"synopsis", value:
"A service running on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of OpenSSL running on the remote
host is 1.1.0 prior to 1.1.0c. It is, therefore, affected by multiple
vulnerabilities :

  - A NULL pointer deference flaw exists, specifically in
    the asn1_item_embed_d2i() function within file
    crypto/asn1/tasn_dec.c, when handling the ASN.1 CHOICE
    type, which results in a NULL value being passed to the
    structure callback if an attempt is made to free certain
    invalid encodings. An unauthenticated, remote attacker
    can exploit this to cause a denial of service condition.
    (CVE-2016-7053)

  - A heap overflow condition exists in the
    chacha20_poly1305_cipher() function within file
    crypto/evp/e_chacha20_poly1305.c when handling TLS
    connections using *-CHACHA20-POLY1305 cipher suites. An
    unauthenticated, remote attacker can exploit this to
    cause a denial of service condition. (CVE-2016-7054)

  - A carry propagation error exists in the
    Broadwell-specific Montgomery multiplication procedure
    when handling input lengths divisible by but longer than
    256 bits. This can result in transient authentication
    and key negotiation failures or reproducible erroneous
    outcomes of public-key operations with specially crafted
    input. An unauthenticated, remote attacker can possibly
    exploit this issue to compromise ECDH key negotiations
    that utilize Brainpool P-512 curves. (CVE-2016-7055)");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20161110.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSL version 1.1.0c or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/11/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("openssl_version.nasl");
  script_require_keys("openssl/port");

  exit(0);
}

include("openssl_version.inc");

openssl_check_version(fixed:'1.1.0c', min:"1.1.0a", severity:SECURITY_WARNING);
