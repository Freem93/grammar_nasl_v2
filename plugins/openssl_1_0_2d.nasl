#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84637);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/10/25 16:58:35 $");

  script_cve_id("CVE-2015-1793", "CVE-2015-3196");
  script_bugtraq_id(75652);
  script_osvdb_id(124300, 131040);
  script_xref(name:"IAVA", value:"2016-A-0293");

  script_name(english:"OpenSSL 1.0.2 < 1.0.2d Multiple Vulnerabilities");
  script_summary(english:"Performs a banner check.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the remote host is running a version of
OpenSSL 1.0.2 prior to 1.0.2d. It is, therefore, affected by the
following vulnerabilities :

  - A certificate validation bypass vulnerability exists due
    to a flaw in the X509_verify_cert() function in
    x509_vfy.c that is triggered when locating alternate
    certificate chains when the first attempt to build such
    a chain fails. A remote attacker can exploit this, by
    using a valid leaf certificate as a certificate
    authority (CA), to issue invalid certificates that will
    bypass authentication. (CVE-2015-1793)

  - A race condition exists in s3_clnt.c that is triggered
    when PSK identity hints are incorrectly updated in the
    parent SSL_CTX structure when they are received by a
    multi-threaded client. A remote attacker can exploit
    this, via a crafted ServerKeyExchange message, to cause
    a double-free memory error, resulting in a denial of
    service. (CVE-2015-3196)");
  script_set_attribute(attribute:"see_also", value:"http://openssl.org/news/secadv_20150709.txt");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20151203.txt");
  # https://github.com/openssl/openssl/commit/2aacec8f4a5ba1b365620a7b17fcce311ada93ad
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fcde170c");
  # https://github.com/openssl/openssl/blob/master/test/verify_extra_test.c#L105
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?59729200");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSL version 1.0.2d or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/09");

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

openssl_check_version(fixed:'1.0.2d', min:"1.0.2", severity:SECURITY_WARNING);
