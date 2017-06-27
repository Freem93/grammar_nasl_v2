#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1901. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44766);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/12/06 20:12:52 $");

  script_cve_id("CVE-2008-5249", "CVE-2008-5250", "CVE-2008-5252", "CVE-2009-0737");
  script_bugtraq_id(32844, 33681);
  script_xref(name:"DSA", value:"1901");

  script_name(english:"Debian DSA-1901-1 : mediawiki1.7 - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in mediawiki1.7, a
website engine for collaborative work. The Common Vulnerabilities and
Exposures project identifies the following problems :

  - CVE-2008-5249
    David Remahl discovered that mediawiki1.7 is prone to a
    cross-site scripting attack.

  - CVE-2008-5250
    David Remahl discovered that mediawiki1.7, when Internet
    Explorer is used and uploads are enabled, or an SVG
    scripting browser is used and SVG uploads are enabled,
    allows remote authenticated users to inject arbitrary
    web script or HTML by editing a wiki page.

  - CVE-2008-5252
    David Remahl discovered that mediawiki1.7 is prone to a
    cross-site request forgery vulnerability in the
    Special:Import feature.

  - CVE-2009-0737
    It was discovered that mediawiki1.7 is prone to a
    cross-site scripting attack in the web-based installer."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=508868"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=508869"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=508870"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=514547"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-5249"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-5250"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-5252"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0737"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1901"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the mediawiki1.7 packages.

For the oldstable distribution (etch), these problems have been fixed
in version 1.7.1-9etch1 for mediawiki1.7, and mediawiki is not
affected (it is a metapackage for mediawiki1.7).

The stable (lenny) distribution does not include mediawiki1.7, and
these problems have been fixed in version 1:1.12.0-2lenny3 for
mediawiki which was already included in the lenny release."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79, 352);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mediawiki1.7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/05");
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
if (deb_check(release:"4.0", prefix:"mediawiki1.7", reference:"1.7.1-9etch1")) flag++;
if (deb_check(release:"4.0", prefix:"mediawiki1.7-math", reference:"1.7.1-9etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
