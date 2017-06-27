#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1805. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(38878);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/12/06 20:12:51 $");

  script_cve_id("CVE-2009-1373", "CVE-2009-1375", "CVE-2009-1376");
  script_bugtraq_id(35067);
  script_xref(name:"DSA", value:"1805");

  script_name(english:"Debian DSA-1805-1 : pidgin - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in Pidgin, a graphical
multi-protocol instant messaging client. The Common Vulnerabilities
and Exposures project identifies the following problems :

  - CVE-2009-1373
    A buffer overflow in the Jabber file transfer code may
    lead to denial of service or the execution of arbitrary
    code.

  - CVE-2009-1375
    Memory corruption in an internal library may lead to
    denial of service.

  - CVE-2009-1376
    The patch provided for the security issue tracked as
    CVE-2008-2927 - integer overflows in the MSN protocol
    handler - was found to be incomplete.

The old stable distribution (etch) is affected under the source
package name gaim. However, due to build problems the updated packages
couldn't be released along with the stable version. It will be
released once the build problem is resolved."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1373"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1375"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1376"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-2927"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1805"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the pidgin packages.

For the stable distribution (lenny), these problems have been fixed in
version 2.4.3-4lenny2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pidgin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/05/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/05/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"finch", reference:"2.4.3-4lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"finch-dev", reference:"2.4.3-4lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"libpurple-bin", reference:"2.4.3-4lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"libpurple-dev", reference:"2.4.3-4lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"libpurple0", reference:"2.4.3-4lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"pidgin", reference:"2.4.3-4lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"pidgin-data", reference:"2.4.3-4lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"pidgin-dbg", reference:"2.4.3-4lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"pidgin-dev", reference:"2.4.3-4lenny2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
