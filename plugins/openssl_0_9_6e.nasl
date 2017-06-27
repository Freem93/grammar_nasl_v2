#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17746);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2017/02/22 19:25:29 $");

  script_cve_id("CVE-2002-0655", "CVE-2002-0656", "CVE-2002-0659");
  script_bugtraq_id(5362, 5363, 5364, 5366);
  script_osvdb_id(857, 3940, 3941, 3943);
  script_xref(name:"CERT-CC", value:"CA-2002-23");
  script_xref(name:"CERT", value:"102795");
  script_xref(name:"CERT", value:"308891");

  script_name(english:"OpenSSL < 0.9.6e Multiple Vulnerabilities");
  script_summary(english:"Does a banner check");

  script_set_attribute(attribute:"synopsis", value:
"The remote server is affected by multiple SSL-related
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the remote server is running a version of
OpenSSL that is earlier than 0.9.6e.  Such versions have the following
vulnerabilities :

  - On 64 bit architectures, these versions are vulnerable 
    to a buffer overflow that leads to a denial of service. 
    (CVE-2002-0655)

  - Buffer overflows allow a remote attacker to execute 
    arbitrary code. (CVE-2002-0656)

  - A remote attacker can trigger a denial of service by 
    sending invalid ASN.1 data. (CVE-2002-0659)");
  script_set_attribute(attribute:"solution", value:"Upgrade to OpenSSL 0.9.6e or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2002/07/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2002/07/30");
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

openssl_check_version(fixed:'0.9.6e', severity:SECURITY_HOLE);
