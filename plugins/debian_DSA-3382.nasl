#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3382. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86665);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/04/28 18:33:24 $");

  script_cve_id("CVE-2014-8958", "CVE-2014-9218", "CVE-2015-2206", "CVE-2015-3902", "CVE-2015-3903", "CVE-2015-6830", "CVE-2015-7873");
  script_osvdb_id(114968, 114969, 114972, 114973, 115322, 119236, 122120, 122121, 127397, 129425);
  script_xref(name:"DSA", value:"3382");

  script_name(english:"Debian DSA-3382-1 : phpmyadmin - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several issues have been fixed in phpMyAdmin, the web administration
tool for MySQL.

  - CVE-2014-8958 (Wheezy only)
    Multiple cross-site scripting (XSS) vulnerabilities.

  - CVE-2014-9218 (Wheezy only)
    Denial of service (resource consumption) via a long
    password.

  - CVE-2015-2206
    Risk of BREACH attack due to reflected parameter.

  - CVE-2015-3902
    XSRF/CSRF vulnerability in phpMyAdmin setup.

  - CVE-2015-3903 (Jessie only)
    Vulnerability allowing man-in-the-middle attack on API
    call to GitHub.

  - CVE-2015-6830 (Jessie only)
    Vulnerability that allows bypassing the reCaptcha test.

  - CVE-2015-7873 (Jessie only)
    Content spoofing vulnerability when redirecting user to
    an external site."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=774194"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-8958"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-9218"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-2206"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-3902"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-3903"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-6830"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-7873"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/phpmyadmin"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/phpmyadmin"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3382"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the phpmyadmin packages.

For the oldstable distribution (wheezy), these problems have been
fixed in version 4:3.4.11.1-2+deb7u2.

For the stable distribution (jessie), these problems have been fixed
in version 4:4.2.12-2+deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:phpmyadmin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"phpmyadmin", reference:"4:3.4.11.1-2+deb7u2")) flag++;
if (deb_check(release:"8.0", prefix:"phpmyadmin", reference:"4:4.2.12-2+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
