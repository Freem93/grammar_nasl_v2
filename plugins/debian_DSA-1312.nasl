#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1312. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25556);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/12/06 20:12:50 $");

  script_cve_id("CVE-2007-1860");
  script_xref(name:"DSA", value:"1312");

  script_name(english:"Debian DSA-1312-1 : libapache-mod-jk - programming error");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that the Apache 1.3 connector for the Tomcat Java
servlet engine decoded request URLs multiple times, which can lead to
information disclosure."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2007/dsa-1312"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libapache-mod-jk package.

For the oldstable distribution (sarge) this problem has been fixed in
version 1.2.5-2sarge1. An updated package for powerpc is not yet
available due to problems with the build host. It will be provided
later.

For the stable distribution (etch) this problem has been fixed in
version 1.2.18-3etch1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cwe_id(20, 22);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libapache-mod-jk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/06/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/06/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"libapache-mod-jk", reference:"1.2.5-2sarge1")) flag++;
if (deb_check(release:"4.0", prefix:"libapache-mod-jk", reference:"1.2.18-3etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libapache-mod-jk-doc", reference:"1.2.18-3etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libapache2-mod-jk", reference:"1.2.18-3etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
