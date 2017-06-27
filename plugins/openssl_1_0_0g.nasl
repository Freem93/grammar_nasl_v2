#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57712);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/09/01 13:42:18 $");

  script_cve_id("CVE-2012-0050");
  script_bugtraq_id(51563);
  script_osvdb_id(78320);

  script_name(english:"OpenSSL 1.0.0f DTLS Denial of Service");
  script_summary(english:"Does a banner check.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host may be affected by a denial of service
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its banner, the remote web server is running OpenSSL
version 1.0.0f.  This version has a flaw in the fix for CVE-2011-4108
such that Datagram Transport Layer Security (DTLS) applications that
use it are vulnerable to a denial of service attack."
  );
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20120118.txt");
  script_set_attribute(attribute:"see_also", value:"http://www.openssl.org/news/changelog.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to OpenSSL 1.0.0g or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("openssl_version.nasl");
  script_require_keys("openssl/port");

  exit(0);
}

include("openssl_version.inc");

openssl_check_version(fixed:'1.0.0g', min:"1.0.0f", severity:SECURITY_WARNING);
