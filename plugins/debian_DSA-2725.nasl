#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2725. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(68971);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/05 14:58:43 $");

  script_cve_id("CVE-2012-3544", "CVE-2013-2067");
  script_bugtraq_id(59797, 59799);
  script_osvdb_id(87223, 87227, 87579, 87580, 88093, 88094, 88095, 93252, 93253);
  script_xref(name:"DSA", value:"2725");

  script_name(english:"Debian DSA-2725-1 : tomcat6 - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two security issues have been found in the Tomcat servlet and JSP
engine :

  - CVE-2012-3544
    The input filter for chunked transfer encodings could
    trigger high resource consumption through malformed CRLF
    sequences, resulting in denial of service.

  - CVE-2013-2067
    The FormAuthenticator module was vulnerable to session
    fixation."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-3544"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2067"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-2733"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-3546"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-4431"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-4534"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-5885"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-5886"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-5887"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/tomcat6"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/tomcat6"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2013/dsa-2725"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the tomcat6 packages.

For the oldstable distribution (squeeze), these problems have been
fixed in version 6.0.35-1+squeeze3. This update also provides fixes
for CVE-2012-2733, CVE-2012-3546, CVE-2012-4431, CVE-2012-4534,
CVE-2012-5885, CVE-2012-5886 and CVE-2012-5887, which were all fixed
for stable already.

For the stable distribution (wheezy), these problems have been fixed
in version 6.0.35-6+deb7u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"libservlet2.5-java", reference:"6.0.35-1+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libservlet2.5-java-doc", reference:"6.0.35-1+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libtomcat6-java", reference:"6.0.35-1+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"tomcat6", reference:"6.0.35-1+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"tomcat6-admin", reference:"6.0.35-1+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"tomcat6-common", reference:"6.0.35-1+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"tomcat6-docs", reference:"6.0.35-1+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"tomcat6-examples", reference:"6.0.35-1+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"tomcat6-user", reference:"6.0.35-1+squeeze3")) flag++;
if (deb_check(release:"7.0", prefix:"libservlet2.4-java", reference:"6.0.35-6+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libservlet2.5-java", reference:"6.0.35-6+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libservlet2.5-java-doc", reference:"6.0.35-6+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libtomcat6-java", reference:"6.0.35-6+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"tomcat6", reference:"6.0.35-6+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"tomcat6-admin", reference:"6.0.35-6+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"tomcat6-common", reference:"6.0.35-6+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"tomcat6-docs", reference:"6.0.35-6+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"tomcat6-examples", reference:"6.0.35-6+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"tomcat6-extras", reference:"6.0.35-6+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"tomcat6-user", reference:"6.0.35-6+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
