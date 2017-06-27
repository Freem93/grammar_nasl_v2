#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2067. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(47589);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/05 14:58:41 $");

  script_cve_id("CVE-2010-1667", "CVE-2010-1668", "CVE-2010-1670", "CVE-2010-2479");
  script_bugtraq_id(41259);
  script_xref(name:"DSA", value:"2067");

  script_name(english:"Debian DSA-2067-1 : mahara - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in mahara, an electronic
portfolio, weblog, and resume builder. The following Common
Vulnerabilities and Exposures project ids identify them :

  - CVE-2010-1667
    Multiple pages performed insufficient input sanitising,
    making them vulnerable to cross-site scripting attacks.

  - CVE-2010-1668
    Multiple forms lacked protection against cross-site
    request forgery attacks, therefore making them
    vulnerable.

  - CVE-2010-1670
    Gregor Anzelj discovered that it was possible to
    accidentally configure an installation of mahara that
    allows access to another user's account without a
    password.

  - CVE-2010-2479
    Certain Internet Explorer-specific cross-site scripting
    vulnerabilities were discovered in HTML Purifier, of
    which a copy is included in the mahara package."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-1667"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-1668"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-1670"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-2479"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2010/dsa-2067"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the mahara packages.

For the stable distribution (lenny), the problems have been fixed in
version 1.0.4-4+lenny6."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mahara");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/05");
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
if (deb_check(release:"5.0", prefix:"mahara", reference:"1.0.4-4+lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"mahara-apache2", reference:"1.0.4-4+lenny6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
