#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-210. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15047);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2013/05/17 23:58:35 $");

  script_cve_id("CVE-2002-1405");
  script_bugtraq_id(5499);
  script_osvdb_id(12657);
  script_xref(name:"DSA", value:"210");

  script_name(english:"Debian DSA-210-1 : lynx - CRLF injection");
  script_summary(english:"Checks dpkg output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"lynx (a text-only web browser) did not properly check for illegal
characters in all places, including processing of command line
options, which could be used to insert extra HTTP headers in a
request.

For Debian GNU/Linux 2.2/potato this has been fixed in version
2.8.3-1.1 of the lynx package and version 2.8.3.1-1.1 of the lynx-ssl
package.

For Debian GNU/Linux 3.0/woody this has been fixed in version
2.8.4.1b-3.2 of the lynx package and version 1:2.8.4.1b-3.1 of the
lynx-ssl package."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2002/dsa-210"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the affected lynx, and lynx-ssl packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lynx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lynx-ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:2.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2002/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2002/08/18");
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
if (deb_check(release:"2.2", prefix:"lynx", reference:"2.8.3-1.1")) flag++;
if (deb_check(release:"2.2", prefix:"lynx-ssl", reference:"2.8.3.1-1.1")) flag++;
if (deb_check(release:"3.0", prefix:"lynx", reference:"2.8.4.1b-3.2")) flag++;
if (deb_check(release:"3.0", prefix:"lynx-ssl", reference:"2.8.4.1b-3.1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
