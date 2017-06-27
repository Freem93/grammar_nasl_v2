#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(57459);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/12 14:46:30 $");

  script_cve_id(
    "CVE-2011-1945",
    "CVE-2011-4108",
    "CVE-2011-4109",
    "CVE-2011-4576",
    "CVE-2011-4577",
    "CVE-2011-4619"
  );
  script_bugtraq_id(51281, 47888);
  script_osvdb_id(74632, 78186, 78187, 78188, 78189, 78190, 78191);
  script_xref(name:"CERT", value:"536044");

  script_name(english:"OpenSSL < 0.9.8s Multiple Vulnerabilities");
  script_summary(english:"Does a banner check");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote web server has multiple SSL-related vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its banner, the remote web server is running a version
of OpenSSL older than 0.9.8s.  Such versions have the following
vulnerabilities :

  - An error exists related to ECDSA signatures and binary
    curves. The implementation of curves over binary fields
    could allow a remote, unauthenticated attacker to
    determine private key material via timing attacks.
    (CVE-2011-1945)

  - The Datagram Transport Layer Security (DTLS)
    implementation is vulnerable to plaintext recovery
    attacks when decrypting in CBC mode. (CVE-2011-4108)

  - A double-free error exists during a policy check
    failure if the flag 'X509_V_FLAG_POLICY_CHECK' is set.
    (CVE-2011-4109)

  - An error exists related to SSLv3.0 records that can 
    lead to disclosure of uninitialized memory because the
    library does not clear all bytes used as block cipher
    padding. (CVE-2011-4576)

  - An error exists related to RFC 3779 processing that can
    allow denial of service attacks. Note that this 
    functionality is not enabled by default and must be
    configured at compile time via the 'enable-rfc3779'
    option. (CVE-2011-4577)

  - An error exists related to handshake restarts for 
    server gated cryptography (SGC) that can allow denial
    of service attacks. (CVE-2011-4619)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://openssl.org/news/secadv_20120104.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.openssl.org/news/changelog.html"
  );
  # Google html cache of AlFardan & Paterson PDF
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c0f10f36"
  );
  script_set_attribute(attribute:"see_also", value:"http://eprint.iacr.org/2011/232.pdf");
  script_set_attribute(attribute:"see_also", value:"http://cvs.openssl.org/chngview?cn=21301");
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to OpenSSL 0.9.8s or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vuln_publication_date", value:"2012/01/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencie("openssl_version.nasl");
  script_require_keys("openssl/port");

  exit(0);
}

include("openssl_version.inc");

openssl_check_version(fixed:make_list('0.9.8s'), severity:SECURITY_HOLE);
