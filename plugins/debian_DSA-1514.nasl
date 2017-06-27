#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1514. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31425);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/12/06 20:12:50 $");

  script_cve_id("CVE-2007-2423", "CVE-2007-2637", "CVE-2008-0780", "CVE-2008-0781", "CVE-2008-0782", "CVE-2008-1098", "CVE-2008-1099");
  script_osvdb_id(36269, 36567, 41778, 41779, 41780, 43145, 43146, 43147);
  script_xref(name:"DSA", value:"1514");

  script_name(english:"Debian DSA-1514-1 : moin - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several remote vulnerabilities have been discovered in MoinMoin, a
Python clone of WikiWiki. The Common Vulnerabilities and Exposures
project identifies the following problems :

  - CVE-2007-2423
    A cross-site-scripting vulnerability has been discovered
    in attachment handling.

  - CVE-2007-2637
    Access control lists for calendars and includes were
    insufficiently enforced, which could lead to information
    disclosure.

  - CVE-2008-0780
    A cross-site-scripting vulnerability has been discovered
    in the login code.

  - CVE-2008-0781
    A cross-site-scripting vulnerability has been discovered
    in attachment handling.

  - CVE-2008-0782
    A directory traversal vulnerability in cookie handling
    could lead to local denial of service by overwriting
    files.

  - CVE-2008-1098
    Cross-site-scripting vulnerabilities have been
    discovered in the GUI editor formatter and the code to
    delete pages.

  - CVE-2008-1099
    The macro code validates access control lists
    insufficiently, which could lead to information
    disclosure."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-2423"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-2637"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-0780"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-0781"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-0782"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-1098"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-1099"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1514"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the moin package.

For the stable distribution (etch), these problems have been fixed in
version 1.5.3-1.2etch1. This update also includes a bugfix with
respect to the encoding of password reminder mails, which doesn't have
security implications.

The old stable distribution (sarge) will not be updated due to the
many changes and support for Sarge ending end of this month anyway.
You're advised to upgrade to the stable distribution if you run
moinmoin."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_cwe_id(22, 79, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:moin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/03/13");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/02/12");
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
if (deb_check(release:"4.0", prefix:"moinmoin-common", reference:"1.5.3-1.2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"python-moinmoin", reference:"1.5.3-1.2etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
