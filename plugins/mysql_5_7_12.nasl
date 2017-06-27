#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90684);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/07/25 14:52:52 $");

  script_cve_id(
    "CVE-2015-3197",
    "CVE-2016-0639",
    "CVE-2016-0642",
    "CVE-2016-0643",
    "CVE-2016-0647",
    "CVE-2016-0648",
    "CVE-2016-0655",
    "CVE-2016-0657",
    "CVE-2016-0659",
    "CVE-2016-0662",
    "CVE-2016-0666",
    "CVE-2016-0667",
    "CVE-2016-0702",
    "CVE-2016-0705",
    "CVE-2016-0797",
    "CVE-2016-0798",
    "CVE-2016-0799",
    "CVE-2016-0800",
    "CVE-2016-2047"
  );
  script_bugtraq_id(
    81810,
    82237,
    83705,
    83733,
    83754,
    83755,
    83763,
    86418,
    86424,
    86433,
    86445,
    86457,
    86484,
    86486,
    86493,
    86495,
    86506,
    86509
  );
  script_osvdb_id(
    133715,
    137322,
    137343,
    137349,
    137328,
    137336,
    137344,
    137332,
    137335,
    137338,
    137341,
    137347,
    135151,
    135150,
    135121,
    134973,
    135096,
    135149,
    133627,
    137150,
    137151,
    137152,
    137153
  );
  script_xref(name:"CERT", value:"257823");
  script_xref(name:"CERT", value:"583776");

  script_name(english:"MySQL 5.7.x < 5.7.12 Multiple Vulnerabilities (DROWN)");
  script_summary(english:"Checks the version of MySQL server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL running on the remote host is 5.7.x prior to
5.7.12. It is, therefore, affected by multiple vulnerabilities :

  - A cipher algorithm downgrade vulnerability exists in the
    bundled version of OpenSSL due to a flaw that is
    triggered when handling cipher negotiation. A remote
    attacker can exploit this to negotiate SSLv2 ciphers and
    complete SSLv2 handshakes even if all SSLv2 ciphers have
    been disabled on the server. Note that this
    vulnerability only exists if the SSL_OP_NO_SSLv2 option
    has not been disabled. (CVE-2015-3197)

  - An unspecified flaw exists in the Pluggable
    Authentication subcomponent that allows an
    unauthenticated, remote attacker to execute arbitrary
    code. (CVE-2016-0639)

  - An unspecified flaw exists in the Federated subcomponent
    that allows an authenticated, remote attacker to impact
    integrity and availability. (CVE-2016-0642)

  - An unspecified flaw exists in the DML subcomponent that
    allows an authenticated, remote attacker to disclose
    sensitive information. (CVE-2016-0643)

  - An unspecified flaw exists in the FTS subcomponent that
    allows an authenticated, remote attacker to cause a
    denial of service condition. (CVE-2016-0647)

  - An unspecified flaw exists in the PS subcomponent that
    allows an authenticated, remote attacker to cause a
    denial of service condition. (CVE-2016-0647)

  - An unspecified flaw exists in the InnoDB subcomponent
    that allows an authenticated, remote attacker to cause a
    denial of service condition. (CVE-2016-0655)

  - An unspecified flaw exists in the JSON subcomponent that
    allows an authenticated, remote attacker to disclose
    sensitive information. (CVE-2016-0657)

  - An unspecified flaw exists in the Optimizer subcomponent
    that allows an authenticated, remote attacker to cause a
    denial of service condition. (CVE-2016-0659)

  - An unspecified flaw exists in the Partition subcomponent
    that allows an authenticated, remote attacker to cause a
    denial of service condition. (CVE-2016-0662)

  - An unspecified flaw exists in the Security: Privileges
    subcomponent that allows an authenticated, remote
    attacker to cause a denial of service condition.
    (CVE-2016-0666)

  - An unspecified flaw exists in the Locking subcomponent
    that allows an authenticated, remote attacker to cause a
    denial of service condition. (CVE-2016-0667)

  - A key disclosure vulnerability exists in the bundled
    version of OpenSSL due to improper handling of
    cache-bank conflicts on the Intel Sandy-bridge
    microarchitecture. An attacker can exploit this to gain
    access to RSA key information. (CVE-2016-0702)

  - A double-free error exists in the bundled version of
    OpenSSL due to improper validation of user-supplied
    input when parsing malformed DSA private keys. A remote
    attacker can exploit this to corrupt memory, resulting
    in a denial of service condition or the execution of
    arbitrary code. (CVE-2016-0705)

  - A NULL pointer dereference flaw exists in the bundled
    version of OpenSSL in the BN_hex2bn() and BN_dec2bn()
    functions. A remote attacker can exploit this to trigger
    a heap corruption, resulting in the execution of
    arbitrary code. (CVE-2016-0797)

  - A denial of service vulnerability exists in the bundled
    version of OpenSSL due to improper handling of invalid
    usernames. A remote attacker can exploit this, via a
    specially crafted username, to leak 300 bytes of memory
    per connection, exhausting available memory resources.
    (CVE-2016-0798)

  - Multiple memory corruption issues exist in the bundled
    version of OpenSSL that allow a remote attacker to cause
    a denial of service condition or the execution of
    arbitrary code. (CVE-2016-0799)

  - A flaw exists in the bundled version of OpenSSL that
    allows a cross-protocol Bleichenbacher padding oracle
    attack known as DROWN (Decrypting RSA with Obsolete and
    Weakened eNcryption). This vulnerability exists due to a
    flaw in the Secure Sockets Layer Version 2 (SSLv2)
    implementation, and it allows captured TLS traffic to be
    decrypted. A man-in-the-middle attacker can exploit this
    to decrypt the TLS connection by utilizing previously
    captured traffic and weak cryptography along with a
    series of specially crafted connections to an SSLv2
    server that uses the same private key. (CVE-2016-0800)

  - A man-in-the-middle spoofing vulnerability exists due to
    the server hostname not being verified to match a domain
    name in the Subject's Common Name (CN) or SubjectAltName
    field of the X.509 certificate. A man-in-the-middle
    attacker can exploit this, by spoofing the TLS/SSL
    server via a certificate that appears valid, to disclose
    sensitive information or manipulate transmitted data.
    (CVE-2016-2047)

  - A flaw exists related to certificate validation due to
    the server hostname not being verified to match a domain
    name in the X.509 certificate. A man-in-the-middle
    attacker can exploit this, by spoofing the TLS/SSL
    server via a certificate that appears valid, to disclose
    sensitive information or manipulate data.
    (VulnDB 137150)

  - An integer overflow condition exists that is triggered
    due to improper validation of user-supplied input when
    processing client handshakes. An authenticated, remote
    attacker can exploit this to cause the server to exit,
    resulting in a denial of service condition.
    (VulnDB 137151)

  - An information disclosure vulnerability exists due to
    overly verbose error messages returning part of the SQL
    statement that produced them. An authenticated, remote
    attacker can exploit this to disclose sensitive
    information. (VulnDB 137152)

  - A flaw exists in InnoDB that is triggered during the
    handling of an ALTER TABLE or ADD COLUMN operation on a
    table with virtual columns. An authenticated, remote
    attacker can exploit this to crash the server, resulting
    in a denial of service condition. (VulnDB 137153)");
  # http://www.oracle.com/technetwork/security-advisory/cpuapr2016v3-2985753.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?855180af");
  script_set_attribute(attribute:"see_also", value:"https://dev.mysql.com/doc/relnotes/mysql/5.7/en/news-5-7-12.html");
  script_set_attribute(attribute:"see_also", value:"https://drownattack.com/");
  script_set_attribute(attribute:"see_also", value:"https://www.drownattack.com/drown-attack-paper.pdf");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL version 5.7.12 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/11/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/22");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("mysql_version.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}

include("mysql_version.inc");

mysql_check_version(fixed:'5.7.12', min:'5.7', severity:SECURITY_HOLE);
