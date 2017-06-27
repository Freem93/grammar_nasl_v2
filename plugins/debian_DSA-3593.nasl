#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3593. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(91447);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/12/06 20:25:09 $");

  script_cve_id("CVE-2015-8806", "CVE-2016-1762", "CVE-2016-1833", "CVE-2016-1834", "CVE-2016-1835", "CVE-2016-1836", "CVE-2016-1837", "CVE-2016-1838", "CVE-2016-1839", "CVE-2016-1840", "CVE-2016-2073", "CVE-2016-3627", "CVE-2016-3705", "CVE-2016-4447", "CVE-2016-4449", "CVE-2016-4483");
  script_osvdb_id(130651, 130653, 133549, 134096, 134833, 136114, 136194, 137962, 137965, 138566, 138567, 138568, 138569, 138570, 138572, 138926, 138928);
  script_xref(name:"DSA", value:"3593");

  script_name(english:"Debian DSA-3593-1 : libxml2 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in libxml2, a library
providing support to read, modify and write XML and HTML files. A
remote attacker could provide a specially crafted XML or HTML file
that, when processed by an application using libxml2, would cause a
denial-of-service against the application, or potentially the
execution of arbitrary code with the privileges of the user running
the application."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=812807"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=813613"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=819006"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=823405"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=823414"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/libxml2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2016/dsa-3593"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libxml2 packages.

For the stable distribution (jessie), these problems have been fixed
in version 2.9.1+dfsg1-5+deb8u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:ND/RC:UR");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:X/RC:R");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxml2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"8.0", prefix:"libxml2", reference:"2.9.1+dfsg1-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libxml2-dbg", reference:"2.9.1+dfsg1-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libxml2-dev", reference:"2.9.1+dfsg1-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libxml2-doc", reference:"2.9.1+dfsg1-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libxml2-utils", reference:"2.9.1+dfsg1-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libxml2-utils-dbg", reference:"2.9.1+dfsg1-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"python-libxml2", reference:"2.9.1+dfsg1-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"python-libxml2-dbg", reference:"2.9.1+dfsg1-5+deb8u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
