#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3283. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84063);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2015/06/29 18:58:19 $");

  script_cve_id("CVE-2015-1158", "CVE-2015-1159");
  script_xref(name:"DSA", value:"3283");

  script_name(english:"Debian DSA-3283-1 : cups - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that CUPS, the Common UNIX Printing System, is
vulnerable to a remotely triggerable privilege escalation via
cross-site scripting and bad print job submission used to replace
cupsd.conf on the CUPS server."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/cups"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/cups"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3283"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the cups packages.

For the oldstable distribution (wheezy), these problems have been
fixed in version 1.5.3-5+deb7u6.

For the stable distribution (jessie), these problems have been fixed
in version 1.7.5-11+deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cups");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"cups", reference:"1.5.3-5+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"cups-bsd", reference:"1.5.3-5+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"cups-client", reference:"1.5.3-5+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"cups-common", reference:"1.5.3-5+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"cups-dbg", reference:"1.5.3-5+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"cups-ppdc", reference:"1.5.3-5+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"cupsddk", reference:"1.5.3-5+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"libcups2", reference:"1.5.3-5+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"libcups2-dev", reference:"1.5.3-5+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"libcupscgi1", reference:"1.5.3-5+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"libcupscgi1-dev", reference:"1.5.3-5+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"libcupsdriver1", reference:"1.5.3-5+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"libcupsdriver1-dev", reference:"1.5.3-5+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"libcupsimage2", reference:"1.5.3-5+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"libcupsimage2-dev", reference:"1.5.3-5+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"libcupsmime1", reference:"1.5.3-5+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"libcupsmime1-dev", reference:"1.5.3-5+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"libcupsppdc1", reference:"1.5.3-5+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"libcupsppdc1-dev", reference:"1.5.3-5+deb7u6")) flag++;
if (deb_check(release:"8.0", prefix:"cups", reference:"1.7.5-11+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"cups-bsd", reference:"1.7.5-11+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"cups-client", reference:"1.7.5-11+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"cups-common", reference:"1.7.5-11+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"cups-core-drivers", reference:"1.7.5-11+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"cups-daemon", reference:"1.7.5-11+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"cups-dbg", reference:"1.7.5-11+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"cups-ppdc", reference:"1.7.5-11+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"cups-server-common", reference:"1.7.5-11+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libcups2", reference:"1.7.5-11+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libcups2-dev", reference:"1.7.5-11+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libcupscgi1", reference:"1.7.5-11+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libcupscgi1-dev", reference:"1.7.5-11+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libcupsimage2", reference:"1.7.5-11+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libcupsimage2-dev", reference:"1.7.5-11+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libcupsmime1", reference:"1.7.5-11+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libcupsmime1-dev", reference:"1.7.5-11+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libcupsppdc1", reference:"1.7.5-11+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libcupsppdc1-dev", reference:"1.7.5-11+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
