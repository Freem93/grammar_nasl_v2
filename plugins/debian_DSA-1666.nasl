#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1666. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(34810);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/12/06 20:12:51 $");

  script_cve_id("CVE-2008-4225", "CVE-2008-4226");
  script_bugtraq_id(32326, 32331);
  script_osvdb_id(49992, 49993);
  script_xref(name:"DSA", value:"1666");

  script_name(english:"Debian DSA-1666-1 : libxml2 - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in the GNOME XML library.
The Common Vulnerabilities and Exposures project identifies the
following problems :

  - CVE-2008-4225
    Drew Yao discovered that missing input sanitising in the
    xmlBufferResize() function may lead to an infinite loop,
    resulting in denial of service.

  - CVE-2008-4226
    Drew Yao discovered that an integer overflow in the
    xmlSAX2Characters() function may lead to denial of
    service or the execution of arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-4225"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-4226"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1666"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libxml2 packages.

For the stable distribution (etch), these problems have been fixed in
version 2.6.27.dfsg-6.

For the upcoming stable distribution (lenny) and the unstable
distribution (sid), these problems have been fixed in version
2.6.32.dfsg-5."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxml2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/11/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/11/18");
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
if (deb_check(release:"4.0", prefix:"libxml2", reference:"2.6.27.dfsg-6")) flag++;
if (deb_check(release:"4.0", prefix:"libxml2-dbg", reference:"2.6.27.dfsg-6")) flag++;
if (deb_check(release:"4.0", prefix:"libxml2-dev", reference:"2.6.27.dfsg-6")) flag++;
if (deb_check(release:"4.0", prefix:"libxml2-doc", reference:"2.6.27.dfsg-6")) flag++;
if (deb_check(release:"4.0", prefix:"libxml2-utils", reference:"2.6.27.dfsg-6")) flag++;
if (deb_check(release:"4.0", prefix:"python-libxml2", reference:"2.6.27.dfsg-6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
