#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1859. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44724);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/12/06 20:12:52 $");

  script_cve_id("CVE-2009-2414", "CVE-2009-2416");
  script_osvdb_id(56985, 56990);
  script_xref(name:"DSA", value:"1859");

  script_name(english:"Debian DSA-1859-1 : libxml2 - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Rauli Kaksonen, Tero Rontti and Jukka Taimisto discovered several
vulnerabilities in libxml2, a library for parsing and handling XML
data files, which can lead to denial of service conditions or possibly
arbitrary code execution in the application using the library. The
Common Vulnerabilities and Exposures project identifies the following
problems :

  - CVE-2009-2416
    An XML document with specially crafted Notation or
    Enumeration attribute types in a DTD definition leads to
    the use of a pointers to memory areas which have already
    been freed.

  - CVE-2009-2414
    Missing checks for the depth of ELEMENT DTD definitions
    when parsing child content can lead to extensive
    stack-growth due to a function recursion which can be
    triggered via a crafted XML document."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-2416"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-2414"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1859"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libxml2 packages.

For the oldstable distribution (etch), this problem has been fixed in
version 2.6.27.dfsg-6+etch1.

For the stable distribution (lenny), this problem has been fixed in
version 2.6.32.dfsg-5+lenny1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_cwe_id(119, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxml2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"libxml2", reference:"2.6.27.dfsg-6+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libxml2-dbg", reference:"2.6.27.dfsg-6+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libxml2-dev", reference:"2.6.27.dfsg-6+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libxml2-doc", reference:"2.6.27.dfsg-6+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libxml2-utils", reference:"2.6.27.dfsg-6+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"python-libxml2", reference:"2.6.27.dfsg-6+etch1")) flag++;
if (deb_check(release:"5.0", prefix:"libxml2", reference:"2.6.32.dfsg-5+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libxml2-dbg", reference:"2.6.32.dfsg-5+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libxml2-dev", reference:"2.6.32.dfsg-5+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libxml2-doc", reference:"2.6.32.dfsg-5+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libxml2-utils", reference:"2.6.32.dfsg-5+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"python-libxml2", reference:"2.6.32.dfsg-5+lenny1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
