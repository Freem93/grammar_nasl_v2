#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2834. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71782);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/02/16 15:43:10 $");

  script_cve_id("CVE-2013-7073", "CVE-2013-7074", "CVE-2013-7075", "CVE-2013-7076", "CVE-2013-7078", "CVE-2013-7079", "CVE-2013-7080", "CVE-2013-7081");
  script_bugtraq_id(64238, 64239, 64240, 64245, 64247, 64248, 64252, 64256);
  script_osvdb_id(100880, 100881, 100882, 100883, 100885, 100886, 100887, 100888);
  script_xref(name:"DSA", value:"2834");

  script_name(english:"Debian DSA-2834-1 : typo3-src - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in TYPO3, a content management
system. This update addresses cross-site scripting, information
disclosure, mass assignment, open redirection and insecure unserialize
vulnerabilities and corresponds to TYPO3-CORE-SA-2013-004."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=731999"
  );
  # http://typo3.org/teams/security/security-bulletins/typo3-core/typo3-core-sa-2013-004/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?efe9a8fd"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/typo3-src"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/typo3-src"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2014/dsa-2834"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the typo3-src packages.

For the oldstable distribution (squeeze), these problems have been
fixed in version 4.3.9+dfsg1-1+squeeze9.

For the stable distribution (wheezy), these problems have been fixed
in version 4.5.19+dfsg1-5+wheezy2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:typo3-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"typo3", reference:"4.3.9+dfsg1-1+squeeze9")) flag++;
if (deb_check(release:"6.0", prefix:"typo3-database", reference:"4.3.9+dfsg1-1+squeeze9")) flag++;
if (deb_check(release:"6.0", prefix:"typo3-src-4.3", reference:"4.3.9+dfsg1-1+squeeze9")) flag++;
if (deb_check(release:"7.0", prefix:"typo3", reference:"4.5.19+dfsg1-5+wheezy2")) flag++;
if (deb_check(release:"7.0", prefix:"typo3-database", reference:"4.5.19+dfsg1-5+wheezy2")) flag++;
if (deb_check(release:"7.0", prefix:"typo3-dummy", reference:"4.5.19+dfsg1-5+wheezy2")) flag++;
if (deb_check(release:"7.0", prefix:"typo3-src-4.5", reference:"4.5.19+dfsg1-5+wheezy2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
