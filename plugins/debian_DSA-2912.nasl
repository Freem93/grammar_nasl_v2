#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2912. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(73691);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/09/02 14:37:22 $");

  script_cve_id("CVE-2014-0429", "CVE-2014-0446", "CVE-2014-0451", "CVE-2014-0452", "CVE-2014-0453", "CVE-2014-0456", "CVE-2014-0457", "CVE-2014-0458", "CVE-2014-0459", "CVE-2014-0460", "CVE-2014-0461", "CVE-2014-0462", "CVE-2014-1876", "CVE-2014-2397", "CVE-2014-2398", "CVE-2014-2403", "CVE-2014-2405", "CVE-2014-2412", "CVE-2014-2414", "CVE-2014-2421", "CVE-2014-2423", "CVE-2014-2427");
  script_bugtraq_id(65568, 66856, 66866, 66873, 66877, 66879, 66881, 66883, 66887, 66891, 66893, 66894, 66902, 66903, 66909, 66910, 66914, 66916, 66918, 66920);
  script_osvdb_id(99711, 101309, 102808, 105866, 105867, 105868, 105869, 105871, 105874, 105877, 105878, 105879, 105880, 105881, 105882, 105884, 105886, 105889, 105891, 105892, 105895, 105897, 105899);
  script_xref(name:"DSA", value:"2912");

  script_name(english:"Debian DSA-2912-1 : openjdk-6 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in OpenJDK, an
implementation of the Oracle Java platform, resulting in the execution
of arbitrary code, breakouts of the Java sandbox, information
disclosure or denial of service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/openjdk-6"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/openjdk-6"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2014/dsa-2912"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the openjdk-6 packages.

For the oldstable distribution (squeeze), these problems have been
fixed in version 6b31-1.13.3-1~deb6u1.

For the stable distribution (wheezy), these problems have been fixed
in version 6b31-1.13.3-1~deb7u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openjdk-6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"icedtea-6-jre-cacao", reference:"6b31-1.13.3-1~deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"openjdk-6-dbg", reference:"6b31-1.13.3-1~deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"openjdk-6-demo", reference:"6b31-1.13.3-1~deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"openjdk-6-doc", reference:"6b31-1.13.3-1~deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"openjdk-6-jdk", reference:"6b31-1.13.3-1~deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"openjdk-6-jre", reference:"6b31-1.13.3-1~deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"openjdk-6-jre-headless", reference:"6b31-1.13.3-1~deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"openjdk-6-jre-lib", reference:"6b31-1.13.3-1~deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"openjdk-6-jre-zero", reference:"6b31-1.13.3-1~deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"openjdk-6-source", reference:"6b31-1.13.3-1~deb6u1")) flag++;
if (deb_check(release:"7.0", prefix:"icedtea-6-jre-cacao", reference:"6b31-1.13.3-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"icedtea-6-jre-jamvm", reference:"6b31-1.13.3-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"openjdk-6-dbg", reference:"6b31-1.13.3-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"openjdk-6-demo", reference:"6b31-1.13.3-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"openjdk-6-doc", reference:"6b31-1.13.3-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"openjdk-6-jdk", reference:"6b31-1.13.3-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"openjdk-6-jre", reference:"6b31-1.13.3-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"openjdk-6-jre-headless", reference:"6b31-1.13.3-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"openjdk-6-jre-lib", reference:"6b31-1.13.3-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"openjdk-6-jre-zero", reference:"6b31-1.13.3-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"openjdk-6-source", reference:"6b31-1.13.3-1~deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
