#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17756);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2017/02/22 19:25:29 $");

  script_cve_id("CVE-2006-4339");
# See also CVE-2006-4340, CVE-2006-5462, CVE-2007-6721
  script_bugtraq_id(19849);
  script_osvdb_id(28549);
  script_xref(name:"CERT", value:"845620");

  script_name(english:"OpenSSL < 0.9.7k / 0.9.8c PKCS Padding RSA Signature Forgery Vulnerability");
  script_summary(english:"Does a banner check");

  script_set_attribute(attribute:"synopsis", value:
"The SSL layer on the remote server does not properly verify
signatures.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the remote server is running a version of 
OpenSSL that is earlier than 0.9.7k or 0.9.8c.

These versions do not properly verify PKCS #1 v1.5 signatures and X509
certificates when the RSA exponent is 3.");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20060905.txt");
  script_set_attribute(attribute:"see_also", value:"http://www.us-cert.gov/cas/techalerts/TA06-333A.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to OpenSSL 0.9.7k / 0.9.8c or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(310);

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/09/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/09/05");
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

openssl_check_version(fixed:make_list('0.9.7k', '0.9.8c'), severity:SECURITY_WARNING);
