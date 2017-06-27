#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-751. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(18667);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2013/05/18 00:15:58 $");

  script_cve_id("CVE-2005-1519");
  script_osvdb_id(16335);
  script_xref(name:"DSA", value:"751");

  script_name(english:"Debian DSA-751-1 : squid - IP spoofing");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The upstream developers have discovered a bug in the DNS lookup code
of Squid, the popular WWW proxy cache. When the DNS client UDP port
(assigned by the operating system at startup) is unfiltered and the
network is not protected from IP spoofing, malicious users can spoof
DNS lookups which could result in users being redirected to arbitrary
web sites."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=309504"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-751"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the squid package.

For the old stable distribution (woody) this problem has been fixed in
version 2.4.6-2woody9.

For the stable distribution (sarge) this problem has already been
fixed in version 2.5.9-9."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squid");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/11");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/05/11");
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
if (deb_check(release:"3.0", prefix:"squid", reference:"2.4.6-2woody9")) flag++;
if (deb_check(release:"3.0", prefix:"squid-cgi", reference:"2.4.6-2woody9")) flag++;
if (deb_check(release:"3.0", prefix:"squidclient", reference:"2.4.6-2woody9")) flag++;
if (deb_check(release:"3.1", prefix:"squid", reference:"2.5.9-9")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
