#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81784);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/24 13:12:22 $");

  script_cve_id(
    "CVE-2014-0139",
    "CVE-2014-3509",
    "CVE-2014-3511",
    "CVE-2014-3566",
    "CVE-2014-4244",
    "CVE-2014-4263",
    "CVE-2014-5139"
  );
  script_bugtraq_id(
    66458,
    68624,
    68636,
    69077,
    69079,
    69084,
    70574
  );
  script_osvdb_id(
    105009,
    109141,
    109142,
    109896,
    109898,
    109902,
    113251
  );
  script_xref(name:"CERT", value:"577193");

  script_name(english:"IBM Rational ClearQuest 7.1.x < 7.1.2.16 / 8.0.0.x < 8.0.0.13 / 8.0.1.x < 8.0.1.6 Multiple Vulnerabilities (credentialed check) (POODLE)");
  script_summary(english:"Checks the version of IBM Rational ClearQuest.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has software installed that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host has a version of IBM Rational ClearQuest 7.1.x prior
to 7.1.2.16 / 8.0.0.x prior to 8.0.0.13 / 8.0.1.x prior to 8.0.1.6
installed. It is, therefore, potentially affected by multiple
vulnerabilities in third party libraries :

  - An error exists in the libcURL and OpenSSL libraries
    related to an IP address that uses a wildcard in the
    subject's Common Name (CN) field of an X.509
    certificate. A man-in-the-middle attacker can exploit
    this issue to spoof SSL servers. (CVE-2014-0139)

  - An error exists in the OpenSSL library related to
    'ec point format extension' handling and multithreaded
    clients that allows freed memory to be overwritten
    during a resumed session. (CVE-2014-3509)
 
  - An error exists in the OpenSSL library related to
    handling fragmented 'ClientHello' messages that allow a
    man-in-the-middle attacker to force usage of TLS 1.0
    regardless of higher protocol levels being supported by
    both the server and the client. (CVE-2014-3511)

  - A man-in-the-middle (MitM) information disclosure
    vulnerability known as POODLE. The vulnerability is due
    to the way SSL 3.0 handles padding bytes when decrypting
    messages encrypted using block ciphers in cipher block
    chaining (CBC) mode. MitM attackers can decrypt a
    selected byte of a cipher text in as few as 256 tries if
    they are able to force a victim application to
    repeatedly send the same data over newly created SSL 3.0
    connections. (CVE-2014-3566)

  - An information disclosure flaw exists in the Java
    library within the
    'share/classes/sun/security/rsa/RSACore.java' class
    related to 'RSA blinding' caused during operations using
    private keys and measuring timing differences. This
    allows a remote attacker to gain information about used
    keys. (CVE-2014-4244)

  - A flaw exists in the Java library within the
    'validateDHPublicKey' function in the
    'share/classes/sun/security/util/KeyUtil.java' class
    which is triggered during the validation of
    Diffie-Hellman public key parameters. This allows a
    remote attacker to recover a key. (CVE-2014-4263)

  - A NULL pointer dereference error exists in the OpenSSL
    library related to handling Secure Remote Password
    protocol (SRP) that allows a malicious server to crash a
    client, resulting in a denial of service.
    (CVE-2014-5139)");
  # OpenSSL
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21692062");
  # POODLE
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21687405");
  # libcURL
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21677290");
  # Java
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21692139");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2014/10/14/poodle.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/~bodo/ssl-poodle.pdf");
  script_set_attribute(attribute:"see_also", value:"https://tools.ietf.org/html/draft-ietf-tls-downgrade-scsv-00");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM Rational ClearQuest 7.1.2.16 / 8.0.0.13 / 8.0.1.6 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/12");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:rational_clearquest");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies('ibm_rational_clearquest_installed.nasl');
  script_require_keys('installed_sw/IBM Rational ClearQuest', "Settings/ParanoidReport");

  exit(0);
}

include('ibm_rational_clearquest_version.inc');

rational_clearquest_check_version(
  fixes:make_nested_list(
    make_array("Min", "7.1.0.0", "Fix UI", "7.1.2.16", "Fix", "7.1216.0.145"),
    make_array("Min", "8.0.0.0", "Fix UI", "8.0.0.13", "Fix", "8.13.0.721"),
    make_array("Min", "8.0.1.0", "Fix UI", "8.0.1.6",  "Fix", "8.106.0.432")),
  severity:SECURITY_WARNING,
  paranoid:TRUE   #only affects Web client component
);
