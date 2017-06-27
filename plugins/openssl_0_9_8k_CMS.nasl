#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17764);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2017/02/22 19:25:29 $");

  script_cve_id("CVE-2009-0591");
  script_bugtraq_id(34256);
  script_osvdb_id(52865);

  script_name(english:"OpenSSL < 0.9.8k Signature Repudiation");
  script_summary(english:"Does a banner check");

  script_set_attribute(attribute:"synopsis", value:
"The remote server is affected by a signature repudiation
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the remote server is running a version of
OpenSSL that is earlier than 0.9.8k.  As such, it may allow a valid
sign to generate invalid signatures which would appear valid and could
be repudiated later. 

This only affects CMS users.  CMS appeared in OpenSSL 0.9.8h.");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20090325.txt");
  script_set_attribute(attribute:"solution", value:"Upgrade to OpenSSL 0.9.8k or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(287);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/03/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/03/25");
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

openssl_check_version(fixed:'0.9.8k', min:'0.9.8h', severity:SECURITY_NOTE);
