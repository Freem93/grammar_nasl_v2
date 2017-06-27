#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17768);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/09/22 20:50:24 $");

  script_cve_id("CVE-2009-1379", "CVE-2009-1387");
  script_bugtraq_id(35138, 35417);
  script_osvdb_id(54614, 55072);

  script_name(english:"OpenSSL 1.0.0 < 1.0.0-beta2 DoS");
  script_summary(english:"Does a banner check");

  script_set_attribute(attribute:"synopsis", value:"The remote server is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the remote server is running a version of
OpenSSL 1.0.0 prior to 1.0.0 beta 2.

A remote attacker can crash the server by sending an out-of-sequence
DTLS handshake message.");
  # http://rt.openssl.org/Ticket/Display.html?id=1838&amp;user=guest&amp;pass=guest
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?80faf91e");
  script_set_attribute(attribute:"see_also", value:"http://cvs.openssl.org/chngview?cn=17958");
  script_set_attribute(attribute:"see_also", value:"http://voodoo-circle.sourceforge.net/sa/sa-20091012-01.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to OpenSSL 1.0.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/02/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

  script_dependencies("openssl_version.nasl");
  script_require_keys("openssl/port");

  exit(0);
}

include("openssl_version.inc");

openssl_check_version(fixed:'1.0.0-beta2', min:'1.0.0-beta0', severity:SECURITY_WARNING);
