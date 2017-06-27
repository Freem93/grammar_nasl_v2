#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57460);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/12 14:46:30 $");

  script_cve_id(
    "CVE-2011-4108",
    "CVE-2011-4576",
    "CVE-2011-4577",
    "CVE-2011-4619",
    "CVE-2012-0027"
  );
  script_bugtraq_id(51281);
  script_osvdb_id(78186, 78187, 78188, 78189, 78190, 78191);

  script_name(english:"OpenSSL 1.x < 1.0.0f Multiple Vulnerabilities");
  script_summary(english:"Does a banner check.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server is affected by multiple SSL-related
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its banner, the remote web server is running a version
of OpenSSL 1.x that is earlier than 1.0.0f. Such versions are affected 
by the following vulnerabilities :

  - The Datagram Transport Layer Security (DTLS)
    implementation is vulnerable to plaintext recovery
    attacks when decrypting in CBC mode. (CVE-2011-4108)

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
    of service attacks. (CVE-2011-4619)

  - An error exists in the GOST implementation that can 
    allow invalid GOST parameters to crash the server.
    (CVE-2012-0027)"
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
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to OpenSSL 1.0.0f or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date",value:"2012/01/04");
  script_set_attribute(attribute:"patch_publication_date",value:"2012/01/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("openssl_version.nasl");
  script_require_keys("openssl/port");

  exit(0);
}

include("openssl_version.inc");

openssl_check_version(fixed:'1.0.0f', min:"1.0.0", severity:SECURITY_WARNING);
