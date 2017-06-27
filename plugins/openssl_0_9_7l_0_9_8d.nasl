#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17757);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2017/02/22 19:25:29 $");

  script_cve_id("CVE-2006-2937", "CVE-2006-3738", "CVE-2006-2940", "CVE-2006-4343");
  script_bugtraq_id(20247, 20248, 20249); # 22083 is for Oracle
  script_osvdb_id(29260, 29261, 29262, 29263);

  script_name(english:"OpenSSL < 0.9.7l / 0.9.8d Multiple Vulnerabilities");
  script_summary(english:"Does a banner check");

  script_set_attribute(attribute:"synopsis", value:
"The remote server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the remote server is running a version of
OpenSSL that is earlier than 0.9.7l or 0.9.8d.  As such, it is
affected by multiple vulnerabilities :

  - A remote attacker could trigger a denial of service, 
    either via malformed ASN.1 structures or specially 
    crafted public keys. (CVE-2006-2937, CVE-2006-3738)

  - A remote attacker could execute arbitrary code on the 
    remote server by exploiting a buffer overflow in the 
    SSL_get_shared_ciphers function. (CVE-2006-2940)

  - A remote attacker could crash a client by sending an 
    invalid server Hello. (CVE-2006-4343)");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20060928.txt");
  script_set_attribute(attribute:"see_also", value:"http://www.us-cert.gov/cas/techalerts/TA06-333A.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to OpenSSL 0.9.7l / 0.9.8d or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

  script_dependencies("openssl_version.nasl");
  script_require_keys("openssl/port");

  exit(0);
}

include("openssl_version.inc");

openssl_check_version(fixed:make_list('0.9.7l', '0.9.8d'), severity:SECURITY_HOLE);
