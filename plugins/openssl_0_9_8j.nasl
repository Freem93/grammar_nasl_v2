#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17762);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/02/22 19:25:29 $");

  script_cve_id("CVE-2008-5077");
  script_bugtraq_id(33150);
  script_osvdb_id(51164);

  script_name(english:"OpenSSL < 0.9.8j Signature Spoofing");
  script_summary(english:"Does a banner check");

  script_set_attribute(attribute:"synopsis", value:
"The remote server is affected by a signature validation bypass
vulnerability.");

  script_set_attribute(attribute:"description", value:
"According to its banner, the remote server is running a version of 
OpenSSL that is earlier than 0.9.8j. 

A remote attacker could implement a man-in-the-middle attack by
forging an SSL/TLS signature using DSA and ECDSA keys which bypass
validation of the certificate chain.");
  script_set_attribute(attribute:"see_also", value:"http://www.us-cert.gov/cas/techalerts/TA09-133A.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to OpenSSL 0.9.8j or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/01/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/01/07");
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

openssl_check_version(fixed:'0.9.8j', severity:SECURITY_WARNING);
