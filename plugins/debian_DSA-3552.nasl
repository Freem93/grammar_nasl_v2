#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3552. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90552);
  script_version("$Revision: 2.8 $");
  script_cvs_date("$Date: 2016/12/06 20:25:08 $");

  script_cve_id("CVE-2015-5174", "CVE-2015-5345", "CVE-2015-5346", "CVE-2015-5351", "CVE-2016-0706", "CVE-2016-0714", "CVE-2016-0763");
  script_osvdb_id(134823, 134824, 134825, 134826, 134827, 134828, 134829);
  script_xref(name:"DSA", value:"3552");

  script_name(english:"Debian DSA-3552-1 : tomcat7 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple security vulnerabilities have been discovered in the Tomcat
servlet and JSP engine, which may result in information disclosure,
the bypass of CSRF protections and bypass of the SecurityManager."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-0119"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-0096"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/tomcat7"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/tomcat7"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2016/dsa-3552"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the tomcat7 packages.

For the oldstable distribution (wheezy), these problems have been
fixed in version 7.0.28-4+deb7u4. This update also fixes CVE-2014-0119
and CVE-2014-0096.

For the stable distribution (jessie), these problems have been fixed
in version 7.0.56-3+deb8u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"libservlet3.0-java", reference:"7.0.28-4+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libservlet3.0-java-doc", reference:"7.0.28-4+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libtomcat7-java", reference:"7.0.28-4+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"tomcat7", reference:"7.0.28-4+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"tomcat7-admin", reference:"7.0.28-4+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"tomcat7-common", reference:"7.0.28-4+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"tomcat7-docs", reference:"7.0.28-4+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"tomcat7-examples", reference:"7.0.28-4+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"tomcat7-user", reference:"7.0.28-4+deb7u4")) flag++;
if (deb_check(release:"8.0", prefix:"libservlet3.0-java", reference:"7.0.56-3+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libservlet3.0-java-doc", reference:"7.0.56-3+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libtomcat7-java", reference:"7.0.56-3+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"tomcat7", reference:"7.0.56-3+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"tomcat7-admin", reference:"7.0.56-3+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"tomcat7-common", reference:"7.0.56-3+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"tomcat7-docs", reference:"7.0.56-3+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"tomcat7-examples", reference:"7.0.56-3+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"tomcat7-user", reference:"7.0.56-3+deb8u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
