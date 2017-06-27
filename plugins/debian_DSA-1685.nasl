#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1685. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35091);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/12/06 20:12:51 $");

  script_cve_id("CVE-2008-5005", "CVE-2008-5006");
  script_xref(name:"DSA", value:"1685");

  script_name(english:"Debian DSA-1685-1 : uw-imap - buffer overflows, NULL pointer dereference");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two vulnerabilities have been found in uw-imap, an IMAP
implementation. The Common Vulnerabilities and Exposures project
identifies the following problems :

It was discovered that several buffer overflows can be triggered via a
long folder extension argument to the tmail or dmail program. This
could lead to arbitrary code execution (CVE-2008-5005 ).

It was discovered that a NULL pointer dereference could be triggered
by a malicious response to the QUIT command leading to a denial of
service (CVE-2008-5006 )."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-5005"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-5006"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1685"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the uw-imap packages.

For the stable distribution (etch), these problems have been fixed in
version 2002edebian1-13.1+etch1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(119, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uw-imap");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/12/15");
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
if (deb_check(release:"4.0", prefix:"ipopd", reference:"2002edebian1-13.1+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"ipopd-ssl", reference:"2002edebian1-13.1+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libc-client-dev", reference:"2002edebian1-13.1+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libc-client2002edebian", reference:"2002edebian1-13.1+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"mlock", reference:"2002edebian1-13.1+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"uw-imapd", reference:"2002edebian1-13.1+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"uw-imapd-ssl", reference:"2002edebian1-13.1+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"uw-mailutils", reference:"2002edebian1-13.1+etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
