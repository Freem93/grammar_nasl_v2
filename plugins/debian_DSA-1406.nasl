#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1406. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(28151);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2014/05/03 11:14:58 $");

  script_cve_id("CVE-2006-3548", "CVE-2006-3549", "CVE-2006-4256", "CVE-2007-1473", "CVE-2007-1474");
  script_osvdb_id(27032, 27033, 27034, 27981, 27982, 33084, 35087);
  script_xref(name:"DSA", value:"1406");

  script_name(english:"Debian DSA-1406-1 : horde3 - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several remote vulnerabilities have been discovered in the Horde web
application framework. The Common Vulnerabilities and Exposures
project identifies the following problems :

  - CVE-2006-3548
    Moritz Naumann discovered that Horde allows remote
    attackers to inject arbitrary web script or HTML in the
    context of a logged in user (cross site scripting).

      This vulnerability applies to oldstable (sarge) only.

  - CVE-2006-3549
    Moritz Naumann discovered that Horde does not properly
    restrict its image proxy, allowing remote attackers to
    use the server as a proxy.

      This vulnerability applies to oldstable (sarge) only.

  - CVE-2006-4256
    Marc Ruef discovered that Horde allows remote attackers
    to include web pages from other sites, which could be
    useful for phishing attacks.

      This vulnerability applies to oldstable (sarge) only.

  - CVE-2007-1473
    Moritz Naumann discovered that Horde allows remote
    attackers to inject arbitrary web script or HTML in the
    context of a logged in user (cross site scripting).

      This vulnerability applies to both stable (etch) and oldstable
      (sarge).

  - CVE-2007-1474
    iDefense discovered that the cleanup cron script in
    Horde allows local users to delete arbitrary files.

      This vulnerability applies to oldstable (sarge) only."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=378281"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=383416"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=434045"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-3548"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-3549"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-4256"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-1473"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-1474"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2007/dsa-1406"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the horde3 package.

For the old stable distribution (sarge) these problems have been fixed
in version 3.0.4-4sarge6.

For the stable distribution (etch) these problems have been fixed in
version 3.1.3-4etch1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:horde3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/12");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/07/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"horde3", reference:"3.0.4-4sarge6")) flag++;
if (deb_check(release:"4.0", prefix:"horde3", reference:"3.1.3-4etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
