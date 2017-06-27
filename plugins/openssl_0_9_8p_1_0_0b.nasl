#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17766);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/02/22 19:25:29 $");

  script_cve_id("CVE-2010-3864");
  script_bugtraq_id(44884);
  script_osvdb_id(69265);

  script_name(english:"OpenSSL < 0.9.8p / 1.0.0b Buffer Overflow");
  script_summary(english:"Does a banner check");

  script_set_attribute(attribute:"synopsis", value:
"The remote server is affected by a buffer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the remote server is running a version of 
OpenSSL that is earlier than 0.9.8p / 1.0.0b.

If a TLS server is multithreaded and uses the SSL cache, a remote
attacker could trigger a buffer overflow and crash the server or run
arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"http://openssl.org/news/secadv_20101116.txt");
  script_set_attribute(attribute:"solution", value:"Upgrade to OpenSSL 0.9.8p / 1.0.0b or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/11/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/16");
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

openssl_check_version(fixed:make_list('0.9.8p', '1.0.0b'), severity:SECURITY_HOLE);
