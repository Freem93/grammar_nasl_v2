#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3508. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89698);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/10/10 14:14:52 $");

  script_cve_id("CVE-2016-1577", "CVE-2016-2089", "CVE-2016-2116");
  script_xref(name:"DSA", value:"3508");

  script_name(english:"Debian DSA-3508-1 : jasper - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in JasPer, a library for
manipulating JPEG-2000 files. The Common Vulnerabilities and Exposures
project identifies the following problems :

  - CVE-2016-1577
    Jacob Baines discovered a double-free flaw in the
    jas_iccattrval_destroy function. A remote attacker could
    exploit this flaw to cause an application using the
    JasPer library to crash, or potentially, to execute
    arbitrary code with the privileges of the user running
    the application.

  - CVE-2016-2089
    The Qihoo 360 Codesafe Team discovered a NULL pointer
    dereference flaw within the jas_matrix_clip function. A
    remote attacker could exploit this flaw to cause an
    application using the JasPer library to crash, resulting
    in a denial-of-service.

  - CVE-2016-2116
    Tyler Hicks discovered a memory leak flaw in the
    jas_iccprof_createfrombuf function. A remote attacker
    could exploit this flaw to cause the JasPer library to
    consume memory, resulting in a denial-of-service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=812978"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=816625"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=816626"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1577"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-2089"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-2116"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/jasper"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/jasper"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2016/dsa-3508"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the jasper packages.

For the oldstable distribution (wheezy), these problems have been
fixed in version 1.900.1-13+deb7u4.

For the stable distribution (jessie), these problems have been fixed
in version 1.900.1-debian1-2.4+deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jasper");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/07");
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
if (deb_check(release:"7.0", prefix:"libjasper-dev", reference:"1.900.1-13+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libjasper-runtime", reference:"1.900.1-13+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libjasper1", reference:"1.900.1-13+deb7u4")) flag++;
if (deb_check(release:"8.0", prefix:"libjasper-dev", reference:"1.900.1-debian1-2.4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libjasper-runtime", reference:"1.900.1-debian1-2.4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libjasper1", reference:"1.900.1-debian1-2.4+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
