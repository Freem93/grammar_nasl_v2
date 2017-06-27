#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87221);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/10/25 16:58:35 $");

  script_cve_id("CVE-2015-3194", "CVE-2015-3195");
  script_bugtraq_id(78623, 78626);
  script_osvdb_id(131038, 131039);
  script_xref(name:"IAVA", value:"2016-A-0293");

  script_name(english:"OpenSSL 1.0.1 < 1.0.1q Multiple DoS");
  script_summary(english:"Performs a banner check.");

  script_set_attribute(attribute:"synopsis", value:
"The remote service is affected by multiple denial of service
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the remote host is running a version of
OpenSSL 1.0.1 prior to 1.0.1q. It is, therefore, affected by the
following vulnerabilities :

  - A NULL pointer dereference flaw exists in file
    rsa_ameth.c when handling ASN.1 signatures that use the
    RSA PSS algorithm but are missing a mask generation
    function parameter. A remote attacker can exploit this
    to cause the signature verification routine to crash,
    leading to a denial of service. (CVE-2015-3194)

  - A flaw exists in the ASN1_TFLG_COMBINE implementation in
    file tasn_dec.c related to handling malformed
    X509_ATTRIBUTE structures. A remote attacker can exploit
    this to cause a memory leak by triggering a decoding
    failure in a PKCS#7 or CMS application, resulting in a
    denial of service. (CVE-2015-3195)");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20151203.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSL version 1.0.1q or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("openssl_version.nasl");
  script_require_keys("openssl/port");

  exit(0);
}

include("openssl_version.inc");

openssl_check_version(fixed:'1.0.1q', min:"1.0.1", severity:SECURITY_WARNING);
