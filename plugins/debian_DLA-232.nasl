#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-232-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83887);
  script_version("$Revision: 2.11 $");
  script_cvs_date("$Date: 2016/05/05 14:49:54 $");

  script_cve_id("CVE-2014-0227", "CVE-2014-0230", "CVE-2014-7810");
  script_bugtraq_id(72717, 74475, 74665);
  script_osvdb_id(118214, 120539, 122158);

  script_name(english:"Debian DLA-232-1 : tomcat6 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The following vulnerabilities were found in Apache Tomcat 6 :

CVE-2014-0227

The Tomcat security team identified that it was possible to conduct
HTTP request smuggling attacks or cause a DoS by streaming malformed
data.

CVE-2014-0230

AntBean@secdig, from the Baidu Security Team, disclosed that it was
possible to cause a limited DoS attack by feeding data by aborting an
upload.

CVE-2014-7810

The Tomcat security team identified that malicious web applications
could bypass the Security Manager by the use of expression language.

For Debian 6 'Squeeze', these issues have been fixed in tomcat6
version 6.0.41-2+squeeze7.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2015/05/msg00016.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/tomcat6"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/29");
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
if (deb_check(release:"6.0", prefix:"libservlet2.4-java", reference:"6.0.41-2+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"libservlet2.5-java", reference:"6.0.41-2+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"libservlet2.5-java-doc", reference:"6.0.41-2+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"libtomcat6-java", reference:"6.0.41-2+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"tomcat6", reference:"6.0.41-2+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"tomcat6-admin", reference:"6.0.41-2+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"tomcat6-common", reference:"6.0.41-2+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"tomcat6-docs", reference:"6.0.41-2+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"tomcat6-examples", reference:"6.0.41-2+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"tomcat6-extras", reference:"6.0.41-2+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"tomcat6-user", reference:"6.0.41-2+squeeze7")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
