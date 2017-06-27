#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17751);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/02/22 19:25:29 $");

  script_cve_id("CVE-2009-0653");
  script_osvdb_id(56452);

  script_name(english:"OpenSSL 0.9.6 CA Basic Constraints Validation Vulnerability");
  script_summary(english:"Does a banner check");

  script_set_attribute(attribute:"synopsis", value:
"The remote server is affected by a certificate validation
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the remote server is running a version of 
OpenSSL that is earlier than 0.9.7. 

Such versions do not verify the Basic Constraint for some
certificates.  A remote attacker could perform a man-in-the-middle
attack. 

Details on this weakness are missing.  It is related to CVE-2002-0970. 
OpenSSL 0.9.6 was reported as 'probably' vulnerable.");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8e41b7c3");
  script_set_attribute(attribute:"solution", value:"Upgrade to OpenSSL 0.9.7 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cwe_id(287);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/07/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2002/12/31");
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

openssl_check_version(fixed:'0.9.7', severity:SECURITY_HOLE);
