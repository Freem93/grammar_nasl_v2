#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1541. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31811);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2014/05/03 11:14:59 $");

  script_cve_id("CVE-2007-5707", "CVE-2007-5708", "CVE-2007-6698", "CVE-2008-0658");
  script_xref(name:"DSA", value:"1541");

  script_name(english:"Debian DSA-1541-1 : openldap2.3 - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several remote vulnerabilities have been discovered in OpenLDAP, a
free implementation of the Lightweight Directory Access Protocol. The
Common Vulnerabilities and Exposures project identifies the following
problems :

  - CVE-2007-5707
    Thomas Sesselmann discovered that slapd could be crashed
    by a malformed modify requests.

  - CVE-2007-5708
    Toby Blade discovered that incorrect memory handling in
    slapo-pcache could lead to denial of service through
    crafted search requests.

  - CVE-2007-6698
    It was discovered that a programming error in the
    interface to the BDB storage backend could lead to
    denial of service through crafted modify requests.

  - CVE-2008-0658
    It was discovered that a programming error in the
    interface to the BDB storage backend could lead to
    denial of service through crafted modrdn requests."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=440632"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=448644"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=465875"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-5707"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-5708"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-6698"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-0658"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1541"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the openldap2.3 packages.

For the stable distribution (etch), these problems have been fixed in
version 2.3.30-5+etch1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openldap2.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/04/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"ldap-utils", reference:"2.3.30-5+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libldap-2.3-0", reference:"2.3.30-5+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"slapd", reference:"2.3.30-5+etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
