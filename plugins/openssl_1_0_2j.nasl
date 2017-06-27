#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93786);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/12/07 20:46:54 $");

  script_cve_id("CVE-2016-7052");
  script_bugtraq_id(93171);
  script_osvdb_id(144804);

  script_name(english:"OpenSSL 1.0.2i CRL Handling NULL Pointer Dereference DoS");
  script_summary(english:"Performs a banner check.");

  script_set_attribute(attribute:"synopsis", value:
"The remote service is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the remote host is running OpenSSL version
1.0.2i. It is, therefore, affected by a denial of service
vulnerability in x509_vfy.c due to improper handling of certificate
revocation lists (CRLs). An unauthenticated, remote attacker can
exploit this, via a specially crafted CRL, to cause a NULL pointer
dereference, resulting in a crash of the service.");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20160926.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSL version 1.0.2j or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("openssl_version.nasl");
  script_require_keys("openssl/port");

  exit(0);
}

include("openssl_version.inc");

openssl_check_version(fixed:'1.0.2j', min:"1.0.2i", severity:SECURITY_WARNING);
