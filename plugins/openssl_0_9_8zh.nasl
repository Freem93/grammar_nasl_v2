#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87219);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/10/25 16:58:35 $");

  script_cve_id("CVE-2015-3195");
  script_bugtraq_id(78626);
  script_osvdb_id(131039);
  script_xref(name:"IAVA", value:"2016-A-0293");

  script_name(english:"OpenSSL 0.9.8 < 0.9.8zh X509_ATTRIBUTE Memory Leak DoS");
  script_summary(english:"Performs a banner check.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the remote host is running a version of
OpenSSL 0.9.8 prior to 0.9.8zh. It is, therefore, affected by a flaw
in the ASN1_TFLG_COMBINE implementation in file tasn_dec.c related to
handling malformed X509_ATTRIBUTE structures. A remote attacker can
exploit this to cause a memory leak by triggering a decoding failure
in a PKCS#7 or CMS application, resulting in a denial of service.");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20151203.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSL version 0.9.8zh or later.");
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

openssl_check_version(fixed:'0.9.8zh', min:"0.9.8", severity:SECURITY_WARNING);
