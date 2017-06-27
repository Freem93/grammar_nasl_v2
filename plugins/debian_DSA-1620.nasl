#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1620. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(33740);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/12/06 20:12:51 $");

  script_cve_id("CVE-2007-2052", "CVE-2007-4965", "CVE-2008-1679", "CVE-2008-1721", "CVE-2008-1887");
  script_bugtraq_id(25696, 28715, 28749);
  script_osvdb_id(35247, 44693);
  script_xref(name:"DSA", value:"1620");

  script_name(english:"Debian DSA-1620-1 : python2.5 - several vulnerabilities");
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

  - CVE-2007-2052
    Piotr Engelking discovered that the strxfrm() function
    of the locale module miscalculates the length of an
    internal buffer, which may result in a minor information
    disclosure.

  - CVE-2007-4965
    It was discovered that several integer overflows in the
    imageop module may lead to the execution of arbitrary
    code, if a user is tricked into processing malformed
    images. This issue is also tracked as CVE-2008-1679 due
    to an initially incomplete patch.

  - CVE-2008-1721
    Justin Ferguson discovered that a buffer overflow in the
    zlib module may lead to the execution of arbitrary code.

  - CVE-2008-1887
    Justin Ferguson discovered that insufficient input
    validation in PyString_FromStringAndSize() may lead to
    the execution of arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-2052"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-4965"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-1679"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-1721"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-1887"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1620"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the python2.5 packages.

For the stable distribution (etch), these problems have been fixed in
version 2.5-5+etch1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python2.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/07/28");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/03/31");
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
if (deb_check(release:"4.0", prefix:"idle-python2.5", reference:"2.5-5+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"python2.5", reference:"2.5-5+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"python2.5-dbg", reference:"2.5-5+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"python2.5-dev", reference:"2.5-5+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"python2.5-examples", reference:"2.5-5+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"python2.5-minimal", reference:"2.5-5+etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
