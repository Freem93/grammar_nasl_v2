#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2334. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56714);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/02/16 15:31:56 $");

  script_cve_id("CVE-2011-2771", "CVE-2011-2772", "CVE-2011-2773");
  script_osvdb_id(76917, 76918, 76919, 77207);
  script_xref(name:"DSA", value:"2334");

  script_name(english:"Debian DSA-2334-1 : mahara - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in Mahara, an electronic
portfolio, weblog, and resume builder :

  - CVE-2011-2771
    Teemu Vesala discovered that missing input sanitising of
    RSS feeds could lead to cross-site scripting.

  - CVE-2011-2772
    Richard Mansfield discovered that insufficient upload
    restrictions allowed denial of service.

  - CVE-2011-2773
    Richard Mansfield discovered that the management of
    institutions was prone to cross-site request forgery.

  - (no CVE ID available yet)

    Andrew Nichols discovered a privilege escalation
    vulnerability in MNet handling."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2771"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2772"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2773"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/mahara"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2334"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the mahara packages.

For the oldstable distribution (lenny), this problem has been fixed in
version 1.0.4-4+lenny11.

For the stable distribution (squeeze), this problem has been fixed in
version 1.2.6-2+squeeze3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mahara");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"mahara", reference:"1.0.4-4+lenny11")) flag++;
if (deb_check(release:"6.0", prefix:"mahara", reference:"1.2.6-2+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"mahara-apache2", reference:"1.2.6-2+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"mahara-mediaplayer", reference:"1.2.6-2+squeeze3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
