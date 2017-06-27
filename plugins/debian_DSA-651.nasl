#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-651. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(16235);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2013/05/18 00:15:57 $");

  script_cve_id("CVE-2005-0094", "CVE-2005-0095");
  script_osvdb_id(12886, 12887);
  script_xref(name:"DSA", value:"651");

  script_name(english:"Debian DSA-651-1 : squid - buffer overflow, integer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in Squid, the internet
object cache, the popular WWW proxy cache. The Common Vulnerabilities
and Exposures Project identifies the following vulnerabilities :

  - CAN-2005-0094
    'infamous41md' discovered a buffer overflow in the
    parser for Gopher responses which will lead to memory
    corruption and usually crash Squid.

  - CAN-2005-0095

    'infamous41md' discovered an integer overflow in the
    receiver of WCCP (Web Cache Communication Protocol)
    messages. An attacker could send a specially crafted UDP
    datagram that will cause Squid to crash."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-651"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the squid package.

For the stable distribution (woody) these problems have been fixed in
version 2.4.6-2woody5."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squid");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/01/25");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/01/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"squid", reference:"2.4.6-2woody5")) flag++;
if (deb_check(release:"3.0", prefix:"squid-cgi", reference:"2.4.6-2woody5")) flag++;
if (deb_check(release:"3.0", prefix:"squidclient", reference:"2.4.6-2woody5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
