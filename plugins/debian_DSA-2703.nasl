#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2703. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66846);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/02/16 15:43:09 $");

  script_cve_id("CVE-2013-1968", "CVE-2013-2112");
  script_bugtraq_id(60264, 60267);
  script_osvdb_id(93795, 93796);
  script_xref(name:"DSA", value:"2703");

  script_name(english:"Debian DSA-2703-1 : subversion - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in Subversion, a version
control system. The Common Vulnerabilities and Exposures project
identifies the following problems :

  - CVE-2013-1968
    Subversion repositories with the FSFS repository data
    store format can be corrupted by newline characters in
    filenames. A remote attacker with a malicious client
    could use this flaw to disrupt the service for other
    users using that repository.

  - CVE-2013-2112
    Subversion's svnserve server process may exit when an
    incoming TCP connection is closed early in the
    connection process. A remote attacker can cause svnserve
    to exit and thus deny service to users of the server."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=711033"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-1968"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2112"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/subversion"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/subversion"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2013/dsa-2703"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the subversion packages.

For the oldstable distribution (squeeze), these problems have been
fixed in version 1.6.12dfsg-7.

For the stable distribution (wheezy), these problems have been fixed
in version 1.6.17dfsg-4+deb7u3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:subversion");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"libapache2-svn", reference:"1.6.12dfsg-7")) flag++;
if (deb_check(release:"6.0", prefix:"libsvn-dev", reference:"1.6.12dfsg-7")) flag++;
if (deb_check(release:"6.0", prefix:"libsvn-doc", reference:"1.6.12dfsg-7")) flag++;
if (deb_check(release:"6.0", prefix:"libsvn-java", reference:"1.6.12dfsg-7")) flag++;
if (deb_check(release:"6.0", prefix:"libsvn-perl", reference:"1.6.12dfsg-7")) flag++;
if (deb_check(release:"6.0", prefix:"libsvn-ruby", reference:"1.6.12dfsg-7")) flag++;
if (deb_check(release:"6.0", prefix:"libsvn-ruby1.8", reference:"1.6.12dfsg-7")) flag++;
if (deb_check(release:"6.0", prefix:"libsvn1", reference:"1.6.12dfsg-7")) flag++;
if (deb_check(release:"6.0", prefix:"python-subversion", reference:"1.6.12dfsg-7")) flag++;
if (deb_check(release:"6.0", prefix:"subversion", reference:"1.6.12dfsg-7")) flag++;
if (deb_check(release:"6.0", prefix:"subversion-tools", reference:"1.6.12dfsg-7")) flag++;
if (deb_check(release:"7.0", prefix:"libapache2-svn", reference:"1.6.17dfsg-4+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libsvn-dev", reference:"1.6.17dfsg-4+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libsvn-doc", reference:"1.6.17dfsg-4+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libsvn-java", reference:"1.6.17dfsg-4+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libsvn-perl", reference:"1.6.17dfsg-4+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libsvn-ruby", reference:"1.6.17dfsg-4+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libsvn-ruby1.8", reference:"1.6.17dfsg-4+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libsvn1", reference:"1.6.17dfsg-4+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"python-subversion", reference:"1.6.17dfsg-4+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"subversion", reference:"1.6.17dfsg-4+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"subversion-tools", reference:"1.6.17dfsg-4+deb7u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
