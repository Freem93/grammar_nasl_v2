#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-081. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(14918);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2013/05/17 23:36:50 $");

  script_cve_id("CVE-2001-0700");
  script_bugtraq_id(2895);
  script_xref(name:"DSA", value:"081");

  script_name(english:"Debian DSA-081-1 : w3m - Buffer Overflow");
  script_summary(english:"Checks dpkg output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"In SNS Advisory No. 32 a buffer overflow vulnerability has been
reported in the routine which parses MIME headers that are returned
from web servers. A malicious web server administrator could exploit
this and let the client web browser execute arbitrary code.

w3m handles MIME headers included in the request/response message of
HTTP communication like any other web browser. A buffer overflow will
occur when w3m receives a MIME encoded header with base64 format.

This problem has been fixed by the maintainer in version
0.1.10+0.1.11pre+kokb23-4 of w3m and w3m-ssl (for the SSL-enabled
version), both for Debian GNU/Linux 2.2."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.lac.co.jp/security/english/snsadv_e/32_e.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2001/dsa-081"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the w3m packages immediately."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:w3m");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:w3m-ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:2.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2001/10/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");
  script_family(english:"Debian Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("debian_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/release")) audit(AUDIT_OS_NOT, "Debian");
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (deb_check(release:"2.2", prefix:"w3m", reference:"0.1.10+0.1.11pre+kokb23-4")) flag++;
if (deb_check(release:"2.2", prefix:"w3m-ssl", reference:"0.1.10+0.1.11pre+kokb23-4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
