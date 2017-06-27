#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-728-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(95454);
  script_version("$Revision: 3.5 $");
  script_cvs_date("$Date: 2017/04/13 13:33:09 $");

  script_cve_id("CVE-2016-0762", "CVE-2016-5018", "CVE-2016-6794", "CVE-2016-6796", "CVE-2016-6797", "CVE-2016-6816", "CVE-2016-8735");
  script_osvdb_id(146348, 146354, 146355, 146356, 146357, 147617, 147619);

  script_name(english:"Debian DLA-728-1 : tomcat6 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple security vulnerabilities have been discovered in the Tomcat
servlet and JSP engine, which may result in possible timing attacks to
determine valid user names, bypass of the SecurityManager, disclosure
of system properties, unrestricted access to global resources,
arbitrary file overwrites, and potentially escalation of privileges.

In addition this update further hardens Tomcat's init and maintainer
scripts to prevent possible privilege escalations. Thanks to Paul
Szabo for the report.

This is probably the last security update of Tomcat 6 which will reach
its end-of-life exactly in one month. We strongly recommend to switch
to another supported version such as Tomcat 7 at your earliest
convenience.

For Debian 7 'Wheezy', these problems have been fixed in version
6.0.45+dfsg-1~deb7u3.

We recommend that you upgrade your tomcat6 packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/12/msg00001.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/tomcat6"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:L");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libservlet2.4-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libservlet2.5-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libservlet2.5-java-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtomcat6-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat6-admin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat6-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat6-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat6-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat6-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat6-user");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"libservlet2.4-java", reference:"6.0.45+dfsg-1~deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libservlet2.5-java", reference:"6.0.45+dfsg-1~deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libservlet2.5-java-doc", reference:"6.0.45+dfsg-1~deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libtomcat6-java", reference:"6.0.45+dfsg-1~deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"tomcat6", reference:"6.0.45+dfsg-1~deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"tomcat6-admin", reference:"6.0.45+dfsg-1~deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"tomcat6-common", reference:"6.0.45+dfsg-1~deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"tomcat6-docs", reference:"6.0.45+dfsg-1~deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"tomcat6-examples", reference:"6.0.45+dfsg-1~deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"tomcat6-extras", reference:"6.0.45+dfsg-1~deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"tomcat6-user", reference:"6.0.45+dfsg-1~deb7u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
