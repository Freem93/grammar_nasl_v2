#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2/17/17. Deprecated by openssl_0_9_8f.nasl.

include("compat.inc");

if (description)
{
  script_id(17758);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2017/02/22 19:25:29 $");

  script_cve_id("CVE-2007-5135");
  script_bugtraq_id(25831);
  script_osvdb_id(29262);

  script_name(english:"OpenSSL < 0.9.7m / 0.9.8e Buffer Overflow (deprecated)");
  script_summary(english:"Does a banner check");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the remote server is running a version of 
OpenSSL that is earlier than 0.9.7m or 0.9.8e.

A remote attacker could trigger a one-byte buffer overflow.  The real
impact is unknown.  Arbitrary code could be run but no functional
exploit was published.

This plugin has been deprecated. Use openssl_0_9_8f.nasl (plugin ID
17760) instead.");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20071012.txt");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/archive/1/480855/100/0/threaded");
  script_set_attribute(attribute:"solution", value:"n/a");

  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189);

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/10/12");
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

exit(0, "This plugin has been deprecated. Use openssl_0_9_8f.nasl (plugin ID 17760) instead.");

include("openssl_version.inc");

openssl_check_version(fixed:make_list('0.9.7m', '0.9.8e'), severity:SECURITY_WARNING);
