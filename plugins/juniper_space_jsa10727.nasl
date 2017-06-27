#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91779);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/07/01 20:11:58 $");

  script_cve_id(
    "CVE-2015-2601",
    "CVE-2015-2613",
    "CVE-2015-2625",
    "CVE-2015-2659",
    "CVE-2015-2808",
    "CVE-2015-4000",
    "CVE-2015-4748",
    "CVE-2015-4749"
  );
  script_bugtraq_id(
    73684,
    74733,
    75854,
    75867,
    75871,
    75877,
    75890,
    75895
  );
  script_osvdb_id(
    117855,
    122331,
    124625,
    124629,
    124630,
    124632,
    124636,
    124639
  );
  script_xref(name:"JSA", value:"JSA10727");

  script_name(english:"Juniper Junos Space < 15.1R2 Multiple Vulnerabilities (JSA10727) (Bar Mitzvah) (Logjam)");
  script_summary(english:"Checks the version of Junos Space.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of Junos
Space running on the remote device is prior to 15.1R2. It is,
therefore, affected by multiple vulnerabilities :

  - A flaw exists in the JCE component in the Oracle Java
    runtime due to various cryptographic operations using
    non-constant time comparisons. An unauthenticated,
    remote attacker can exploit this, via timing attacks,
    to disclose potentially sensitive information.
    (CVE-2015-2601)

  - A flaw exists in the JCE component in the Oracle Java
    runtime, within the ECDH_Derive() function, due to
    missing EC parameter validation when performing ECDH key
    derivation. A remote attacker can exploit this to
    disclose potentially sensitive information.
    (CVE-2015-2613)

  - A flaw exists in the JSSE component in the Oracle Java
    runtime, related to performing X.509 certificate identity
    checks, that allows a remote attacker to disclose
    potentially sensitive information. (CVE-2015-2625)

  - A NULL pointer dereference flaw exists in the Security
    component in the Oracle Java runtime, which is related
    to the GCM (Galois Counter Mode) implementation when
    performing encryption using a block cipher in GCM mode.
    An unauthenticated, remote attacker can exploit this to
    cause a denial of service condition. (CVE-2015-2659)

  - A security feature bypass vulnerability exists, known as
    Bar Mitzvah, due to improper combination of state data
    with key data by the RC4 cipher algorithm during the
    initialization phase. A man-in-the-middle attacker can
    exploit this, via a brute-force attack using LSB values,
    to decrypt the traffic. (CVE-2015-2808)

  - A man-in-the-middle vulnerability, known as Logjam,
    exists due to a flaw in the SSL/TLS protocol. A remote
    attacker can exploit this flaw to downgrade connections
    using ephemeral Diffie-Hellman key exchange to 512-bit
    export-grade cryptography. (CVE-2015-4000)

  - A flaw exists in the Security component in the Oracle
    Java runtime when handling Online Certificate Status
    Protocol (OCSP) responses with no 'nextUpdate' date
    specified. A remote attacker can exploit this to cause a
    revoked X.509 certificate to be accepted.
    (CVE-2015-4748)

  - A flaw exists in the JNDI component in the Oracle Java
    runtime, within the DnsClient::query() function, due to
    a failure by DnsClient exception handling to release
    request information. An unauthenticated, remote attacker
    can exploit this to cause a denial of service condition.
    (CVE-2015-4749)");
  # https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10727&actp=search
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a84b985b");
  # # https://www.blackhat.com/docs/asia-15/materials/asia-15-Mantin-Bar-Mitzvah-Attack-Breaking-SSL-With-13-Year-Old-RC4-Weakness-wp.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4bbf45ac");
  script_set_attribute(attribute:"see_also", value:"https://weakdh.org/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Junos Space version 15.1R2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:juniper:junos_space");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Junos_Space/version");

  exit(0);
}

include("junos.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit('Host/Junos_Space/version');

check_junos_space(ver:ver, fix:'15.1R2', severity:SECURITY_HOLE);
