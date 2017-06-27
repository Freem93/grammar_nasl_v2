#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17755);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/02/22 19:25:29 $");

  script_cve_id("CVE-2005-2969");
  script_bugtraq_id(15071);
  script_osvdb_id(19919);

  script_name(english:"OpenSSL < 0.9.7h / 0.9.8a Protocol Version Rollback");
  script_summary(english:"Does a banner check");

  script_set_attribute(attribute:"synopsis", value:
"The remote server is vulnerable to man-in-the-middle attacks.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the remote server is running a version of 
OpenSSL that is earlier than 0.9.7h or 0.9.8a. 

If the SSL_OP_MSIE_SSLV2_RSA_PADDING option is used, a remote attacker
could force a client to downgrade to a weaker protocol and implement a
man-in-the-middle attack.");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20051011.txt");
  script_set_attribute(attribute:"solution", value:"Upgrade to OpenSSL 0.9.7h / 0.9.8a or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/10/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/10/11");
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

openssl_check_version(fixed:make_list('0.9.7h', '0.9.8a'), severity:SECURITY_WARNING);
