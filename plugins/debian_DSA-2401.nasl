#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2401. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57812);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/02/16 15:31:57 $");

  script_cve_id("CVE-2011-1184", "CVE-2011-2204", "CVE-2011-2526", "CVE-2011-3190", "CVE-2011-3375", "CVE-2011-4858", "CVE-2011-5062", "CVE-2011-5063", "CVE-2011-5064", "CVE-2012-0022");
  script_bugtraq_id(48456, 48667, 49353, 49762, 51200, 51442, 51447);
  script_osvdb_id(73429, 73797, 73798, 74818, 76189, 78113, 78331, 78483, 78573, 78598, 78599, 78600);
  script_xref(name:"DSA", value:"2401");

  script_name(english:"Debian DSA-2401-1 : tomcat6 - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been found in Tomcat, a servlet and JSP
engine :

  - CVE-2011-1184 CVE-2011-5062 CVE-2011-5063 CVE-2011-5064
    The HTTP Digest Access Authentication implementation
    performed insufficient countermeasures against replay
    attacks.

  - CVE-2011-2204
    In rare setups passwords were written into a logfile.

  - CVE-2011-2526
    Missing input sanitising in the HTTP APR or HTTP NIO
    connectors could lead to denial of service.

  - CVE-2011-3190
    AJP requests could be spoofed in some setups.

  - CVE-2011-3375
    Incorrect request caching could lead to information
    disclosure.

  - CVE-2011-4858 CVE-2012-0022
    This update adds countermeasures against a collision
    denial of service vulnerability in the Java hashtable
    implementation and addresses denial of service
    potentials when processing large amounts of requests.

Additional information can be found at"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1184"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-5062"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-5063"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-5064"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2204"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2526"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-3190"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-3375"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-4858"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-0022"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/tomcat6"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2012/dsa-2401"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the tomcat6 packages.

For the stable distribution (squeeze), this problem has been fixed in
version 6.0.35-1+squeeze2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"libservlet2.5-java", reference:"6.0.35-1+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libservlet2.5-java-doc", reference:"6.0.35-1+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libtomcat6-java", reference:"6.0.35-1+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"tomcat6", reference:"6.0.35-1+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"tomcat6-admin", reference:"6.0.35-1+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"tomcat6-common", reference:"6.0.35-1+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"tomcat6-docs", reference:"6.0.35-1+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"tomcat6-examples", reference:"6.0.35-1+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"tomcat6-user", reference:"6.0.35-1+squeeze2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
