#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1779. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(38158);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2014/05/03 11:20:10 $");

  script_cve_id("CVE-2009-1300", "CVE-2009-1358");
  script_osvdb_id(56289, 56433);
  script_xref(name:"DSA", value:"1779");

  script_name(english:"Debian DSA-1779-1 : apt - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two vulnerabilities have been discovered in APT, the well-known dpkg
frontend. The Common Vulnerabilities and Exposures project identifies
the following problems :

  - CVE-2009-1300
    In time zones where daylight savings time occurs at
    midnight, the apt cron.daily script fails, stopping new
    security updates from being applied automatically.

  - CVE-2009-1358
    A repository that has been signed with an expired or
    revoked OpenPGP key would still be considered valid by
    APT."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=523213"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=433091"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1300"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1358"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1779"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the apt package.

For the old stable distribution (etch), these problems have been fixed
in version 0.6.46.4-0.1+etch1.

For the stable distribution (lenny), these problems have been fixed in
version 0.7.20.2+lenny1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"apt", reference:"0.6.46.4-0.1+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"apt-doc", reference:"0.6.46.4-0.1+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"apt-utils", reference:"0.6.46.4-0.1+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libapt-pkg-dev", reference:"0.6.46.4-0.1+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libapt-pkg-doc", reference:"0.6.46.4-0.1+etch1")) flag++;
if (deb_check(release:"5.0", prefix:"apt", reference:"0.7.20.2+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"apt-doc", reference:"0.7.20.2+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"apt-transport-https", reference:"0.7.20.2+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"apt-utils", reference:"0.7.20.2+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libapt-pkg-dev", reference:"0.7.20.2+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libapt-pkg-doc", reference:"0.7.20.2+lenny1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
