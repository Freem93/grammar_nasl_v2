#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17763);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/12/07 20:46:54 $");

  script_cve_id(
    "CVE-2009-0590",
    "CVE-2009-0591",
    "CVE-2009-0789",
    "CVE-2009-5146"
  );
  script_bugtraq_id(34256, 73121);
  script_osvdb_id(
    52864,
    52865,
    52866,
    119817
  );

  script_name(english:"OpenSSL < 0.9.8k Multiple Vulnerabilities");
  script_summary(english:"Performs a banner check.");

  script_set_attribute(attribute:"synopsis", value:
"The remote server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the remote server is running a version of
OpenSSL prior to 0.9.8k. It is, therefore, affected by multiple
vulnerabilities :

  - A denial of service vulnerability exists in the
    ASN1_STRING_print_ex() function due to improper string
    handling. A remote attacker can exploit this to cause an
    invalid memory access and application crash.
    (CVE-2009-0590)

  - A flaw exists in the CMS_verify() function due to
    improper handling of errors associated with malformed
    signed attributes. A remote attacker can exploit this to
    repudiate a signature that originally appeared to be
    valid but was actually invalid. (CVE-2009-0591)

  - A denial of service vulnerability exists due to improper
    handling of malformed ASN.1 structures. A remote
    attacker can exploit this to cause an invalid memory
    access and application crash. (CVE-2009-0789)

  - A memory leak exists in the SSL_free() function in
    ssl_lib.c. A remote attacker can exploit this to exhaust
    memory resources, resulting in a denial of service
    condition. (CVE-2009-5146)");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20090325.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSL version 0.9.8k or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119, 189, 287);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/03/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/03/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/04");

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

openssl_check_version(fixed:'0.9.8k', severity:SECURITY_WARNING);
