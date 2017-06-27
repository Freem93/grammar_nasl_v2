#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1667. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(34823);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/12/06 20:12:51 $");

  script_cve_id("CVE-2008-2315", "CVE-2008-3142", "CVE-2008-3143", "CVE-2008-3144");
  script_xref(name:"DSA", value:"1667");

  script_name(english:"Debian DSA-1667-1 : python2.4 - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in the interpreter for
the Python language. The Common Vulnerabilities and Exposures project
identifies the following problems :

  - CVE-2008-2315
    David Remahl discovered several integer overflows in the
    stringobject, unicodeobject, bufferobject, longobject,
    tupleobject, stropmodule, gcmodule, and mmapmodule
    modules.

  - CVE-2008-3142
    Justin Ferguson discovered that incorrect memory
    allocation in the unicode_resize() function can lead to
    buffer overflows.

  - CVE-2008-3143
    Several integer overflows were discovered in various
    Python core modules.

  - CVE-2008-3144
    Several integer overflows were discovered in the
    PyOS_vsnprintf() function."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-2315"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-3142"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-3143"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-3144"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1667"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the python2.4 packages.

For the stable distribution (etch), these problems have been fixed in
version 2.4.4-3+etch2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python2.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/11/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"idle-python2.4", reference:"2.4.4-3+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"python2.4", reference:"2.4.4-3+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"python2.4-dbg", reference:"2.4.4-3+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"python2.4-dev", reference:"2.4.4-3+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"python2.4-examples", reference:"2.4.4-3+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"python2.4-minimal", reference:"2.4.4-3+etch2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
