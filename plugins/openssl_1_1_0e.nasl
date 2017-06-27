#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97328);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/02/27 16:20:34 $");

  script_cve_id("CVE-2017-3733");
  script_osvdb_id(152207);
  script_xref(name:"IAVA", value:"2017-A-0044");

  script_name(english:"OpenSSL 1.1.0 < 1.1.0e Encrypt-Then-Mac Extension DoS");
  script_summary(english:"Performs a banner check.");

  script_set_attribute(attribute:"synopsis", value:
"A service running on the remote host is affected by a denial of
service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of OpenSSL running on the remote
host is 1.1.0 prior to 1.1.0e. It is, therefore, affected by a denial
of service vulnerability that is triggered during a renegotiation
handshake in which the Encrypt-Then-Mac extension is negotiated when
it was not in the original handshake or vice-versa. An
unauthenticated, remote attacker can exploit this issue to cause
OpenSSL to crash, depending on which cipher suite is being used. Note
that both clients and servers are affected.");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20170216.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSL version 1.1.0e or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/02/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("openssl_version.nasl");
  script_require_keys("openssl/port");

  exit(0);
}

include("openssl_version.inc");

openssl_check_version(fixed:'1.1.0e', min:"1.1.0", severity:SECURITY_HOLE);
