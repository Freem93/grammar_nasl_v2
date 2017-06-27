#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3447. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87979);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/04/28 18:33:24 $");

  script_cve_id("CVE-2014-7810");
  script_osvdb_id(122158);
  script_xref(name:"DSA", value:"3447");

  script_name(english:"Debian DSA-3447-1 : tomcat7 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that malicious web applications could use the
Expression Language to bypass protections of a Security Manager as
expressions were evaluated within a privileged code section."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-4444"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-0075"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-0099"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-0227"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-0230"
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
    value:"http://www.debian.org/security/2016/dsa-3447"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the tomcat7 packages.

For the oldstable distribution (wheezy), this problem has been fixed
in version 7.0.28-4+deb7u3. This update also provides fixes for
CVE-2013-4444, CVE-2014-0075, CVE-2014-0099, CVE-2014-0227 and
CVE-2014-0230, which were all fixed for the stable distribution
(jessie) already.

For the stable distribution (jessie), this problem has been fixed in
version 7.0.56-3+deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/19");
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
if (deb_check(release:"7.0", prefix:"libservlet3.0-java", reference:"7.0.28-4+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libservlet3.0-java-doc", reference:"7.0.28-4+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libtomcat7-java", reference:"7.0.28-4+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"tomcat7", reference:"7.0.28-4+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"tomcat7-admin", reference:"7.0.28-4+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"tomcat7-common", reference:"7.0.28-4+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"tomcat7-docs", reference:"7.0.28-4+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"tomcat7-examples", reference:"7.0.28-4+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"tomcat7-user", reference:"7.0.28-4+deb7u3")) flag++;
if (deb_check(release:"8.0", prefix:"libservlet3.0-java", reference:"7.0.56-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libservlet3.0-java-doc", reference:"7.0.56-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libtomcat7-java", reference:"7.0.56-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"tomcat7", reference:"7.0.56-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"tomcat7-admin", reference:"7.0.56-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"tomcat7-common", reference:"7.0.56-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"tomcat7-docs", reference:"7.0.56-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"tomcat7-examples", reference:"7.0.56-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"tomcat7-user", reference:"7.0.56-3+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
