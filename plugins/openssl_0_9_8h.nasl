#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(56996);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/12/07 20:46:54 $");

  script_cve_id("CVE-2008-0891", "CVE-2008-1672", "CVE-2011-4354");
  script_bugtraq_id(29405, 50882);
  script_osvdb_id(45660, 45661, 77650);
  script_xref(name:"CERT", value:"520586");
  script_xref(name:"CERT", value:"661475");

  script_name(english:"OpenSSL < 0.9.8h Multiple Vulnerabilities");
  script_summary(english:"Does a banner check");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote web server has multiple SSL-related vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its banner, the remote web server uses a version of
OpenSSL older than 0.9.8h.  As such, it may be affected by the
following vulnerabilities :

  - A double-free error exists related to the handling of
    server name extension data and specially crafted TLS
    1.0 'Client Hello' packets. This can cause application
    crashes. Note that successful exploitation requires that
    OpenSSL is compiled with the TLS server name extensions.
    (CVE-2008-0891)

  - A NULL pointer dereference error exists related to 
    anonymous Diffie-Hellman key exchange and TLS
    handshakes. This can be exploited by omitting the 
    'Server Key exchange message' from the handshake and
    can cause application crashes. (CVE-2008-1672)

  - On 32-bit builds, an information disclosure
    vulnerability exists during certain calculations for 
    NIST elliptic curves P-256 or P-384. This error can
    allow an attacker to recover the private key of the TLS
    server. 

    The following are required for exploitation :

      - 32-bit build
      - Use of elliptic curves P-256 and/or P-384
      - Either the use of ECDH family ciphers and/or the 
        use of ECDHE family ciphers without the
        SSL_OP_SINGLE_ECDH_USE context option 

    (CVE-2011-4354)

Note that Nessus has not attempted to verify that these issues are
actually exploitable or have been patched but instead has relied on
the version number found in the Server response header."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.openwall.com/lists/oss-security/2011/12/01/6"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.openssl.org/news/secadv/20080528.txt"
  );
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSL 0.9.8h or later or apply the vendor-supplied
patches.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189, 287);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/05/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/05/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("openssl_version.nasl");
  script_require_keys("openssl/port");

  exit(0);
}


include("openssl_version.inc");

openssl_check_version(fixed:'0.9.8h', severity:SECURITY_WARNING);
