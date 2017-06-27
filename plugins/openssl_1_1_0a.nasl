#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93816);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/12/07 20:46:54 $");

  script_cve_id(
    "CVE-2016-6304",
    "CVE-2016-6305",
    "CVE-2016-6307",
    "CVE-2016-6308"
  );
  script_bugtraq_id(
    93149,
    93150,
    93151,
    93152
  );
  script_osvdb_id(
    144680,
    144688,
    144689,
    144690,
    144759
  );

  script_name(english:"OpenSSL 1.1.0 < 1.1.0a Multiple Vulnerabilities");
  script_summary(english:"Performs a banner check.");

  script_set_attribute(attribute:"synopsis", value:
"The remote service is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the remote host is running a version of
OpenSSL 1.1.0 prior to 1.1.0a. It is, therefore, affected by the
following vulnerabilities :

  - A flaw exists in the ssl_parse_clienthello_tlsext()
    function in t1_lib.c due to improper handling of overly
    large OCSP Status Request extensions from clients. An
    unauthenticated, remote attacker can exploit this, via
    large OCSP Status Request extensions, to exhaust memory
    resources, resulting in a denial of service condition.
    (CVE-2016-6304)

  - A flaw exists in the SSL_peek() function in
    rec_layer_s3.c due to improper handling of empty
    records. An unauthenticated, remote attacker can exploit
    this, by triggering a zero-length record in an SSL_peek
    call, to cause an infinite loop, resulting in a denial
    of service condition. (CVE-2016-6305)

  - A denial of service vulnerability exists in the
    state-machine implementation due to a failure to check
    for an excessive length before allocating memory. An
    unauthenticated, remote attacker can exploit this, via a
    crafted TLS message, to exhaust memory resources.
    (CVE-2016-6307)

  - A denial of service vulnerability exists in the DTLS
    implementation due to improper handling of excessively
    long DTLS messages. An unauthenticated, remote attacker
    can exploit this, via a crafted DTLS message, to exhaust
    available memory resources. (CVE-2016-6308)

  - A flaw exists in the GOST ciphersuites due to the use of
    long-term keys to establish an encrypted connection. A
    man-in-the-middle attacker can exploit this, via a Key
    Compromise Impersonation (KCI) attack, to impersonate
    the server. (VulnDB 144759)");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20160922.txt");
  # https://github.com/openssl/openssl/commit/41b42807726e340538701021cdc196672330f4db
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?09b29b30");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSL version 1.1.0a or later.

Note that the GOST ciphersuites vulnerability (VulnDB 144759) is not
yet fixed by the vendor in an official release; however, a patch for
the issue has been committed to the OpenSSL github repository.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/08/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("openssl_version.nasl");
  script_require_keys("openssl/port");

  exit(0);
}

include("openssl_version.inc");

openssl_check_version(fixed:'1.1.0a', min:"1.1.0", severity:SECURITY_HOLE);
