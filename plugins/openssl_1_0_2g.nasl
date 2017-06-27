#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89082);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/07/19 18:40:13 $");

  script_cve_id(
    "CVE-2016-0702",
    "CVE-2016-0705",
    "CVE-2016-0797",
    "CVE-2016-0798",
    "CVE-2016-0799",
    "CVE-2016-0800"
  );
  script_bugtraq_id(
    83705,
    83733,
    83754,
    83755,
    83763
  );
  script_osvdb_id(
    134973,
    135095,
    135096,
    135121,
    135149,
    135150,
    135151
  );
  script_xref(name:"CERT", value:"583776");

  script_name(english:"OpenSSL 1.0.2 < 1.0.2g Multiple Vulnerabilities (DROWN)");
  script_summary(english:"Performs a banner check.");

  script_set_attribute(attribute:"synopsis", value:
"The remote service is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the remote host is running a version of
OpenSSL 1.0.2 prior to 1.0.2g. It is, therefore, affected by the
following vulnerabilities :

  - A key disclosure vulnerability exists due to improper
    handling of cache-bank conflicts on the Intel
    Sandy-bridge microarchitecture. An attacker can exploit
    this to gain access to RSA key information.
    (CVE-2016-0702)

  - A double-free error exists due to improper validation of
    user-supplied input when parsing malformed DSA private
    keys. A remote attacker can exploit this to corrupt
    memory, resulting in a denial of service condition or
    the execution of arbitrary code. (CVE-2016-0705)

  - A NULL pointer dereference flaw exists in the
    BN_hex2bn() and BN_dec2bn() functions. A remote attacker
    can exploit this to trigger a heap corruption, resulting
    in the execution of arbitrary code. (CVE-2016-0797)

  - A denial of service vulnerability exists due to improper
    handling of invalid usernames. A remote attacker can
    exploit this, via a specially crafted username, to leak
    300 bytes of memory per connection, exhausting available
    memory resources. (CVE-2016-0798)

  - Multiple memory corruption issues exist that allow a
    remote attacker to cause a denial of service condition
    or the execution of arbitrary code. (CVE-2016-0799)

  - A flaw exists that allows a cross-protocol
    Bleichenbacher padding oracle attack known as DROWN
    (Decrypting RSA with Obsolete and Weakened eNcryption).
    This vulnerability exists due to a flaw in the Secure
    Sockets Layer Version 2 (SSLv2) implementation, and it
    allows captured TLS traffic to be decrypted. A
    man-in-the-middle attacker can exploit this to decrypt
    the TLS connection by utilizing previously captured
    traffic and weak cryptography along with a series of
    specially crafted connections to an SSLv2 server that
    uses the same private key. (CVE-2016-0800)");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20160301.txt");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/cl102.txt");
  script_set_attribute(attribute:"see_also", value:"https://drownattack.com/");
  script_set_attribute(attribute:"see_also", value:"https://www.drownattack.com/drown-attack-paper.pdf");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSL version 1.0.2g or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("openssl_version.nasl");
  script_require_keys("openssl/port");

  exit(0);
}

include("openssl_version.inc");

openssl_check_version(fixed:'1.0.2g', min:"1.0.2", severity:SECURITY_HOLE);
