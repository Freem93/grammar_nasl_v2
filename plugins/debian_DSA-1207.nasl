#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1207. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(23656);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2014/05/03 11:14:58 $");

  script_cve_id("CVE-2005-3621", "CVE-2005-3665", "CVE-2006-1678", "CVE-2006-2418", "CVE-2006-5116");
  script_osvdb_id(20910, 21486, 21487, 24450, 25563, 29240, 30140, 30141);
  script_xref(name:"DSA", value:"1207");

  script_name(english:"Debian DSA-1207-2 : phpmyadmin - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The phpmyadmin update in DSA 1207 introduced a regression. This update
corrects this flaw. For completeness, please find below the original
advisory text :

  Several remote vulnerabilities have been discovered in phpMyAdmin, a
  program to administrate MySQL over the web. The Common
  Vulnerabilities and Exposures project identifies the following
  problems :

    - CVE-2005-3621
      CRLF injection vulnerability allows remote attackers
      to conduct HTTP response splitting attacks.

    - CVE-2005-3665
      Multiple cross-site scripting (XSS) vulnerabilities
      allow remote attackers to inject arbitrary web script
      or HTML via the (1) HTTP_HOST variable and (2) various
      scripts in the libraries directory that handle header
      generation.

    - CVE-2006-1678
      Multiple cross-site scripting (XSS) vulnerabilities
      allow remote attackers to inject arbitrary web script
      or HTML via scripts in the themes directory.

    - CVE-2006-2418
      A cross-site scripting (XSS) vulnerability allows
      remote attackers to inject arbitrary web script or
      HTML via the db parameter of footer.inc.php.

    - CVE-2006-5116
      A remote attacker could overwrite internal variables
      through the _FILES global variable."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=339437"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=340438"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=362567"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=368082"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=391090"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2005-3621"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2005-3665"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-1678"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-2418"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-5116"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2006/dsa-1207"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the phpmyadmin package.

For the stable distribution (sarge) these problems have been fixed in
version 2.6.2-3sarge3.

For the upcoming stable release (etch) and unstable distribution (sid)
these problems have been fixed in version 2.9.0.3-1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:phpmyadmin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"plugin_publication_date", value:"2006/11/20");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/11/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"phpmyadmin", reference:"2.6.2-3sarge3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
