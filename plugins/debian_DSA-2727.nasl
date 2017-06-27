#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2727. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(69084);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/05/19 17:45:44 $");

  script_cve_id("CVE-2013-1500", "CVE-2013-1571", "CVE-2013-2407", "CVE-2013-2412", "CVE-2013-2443", "CVE-2013-2444", "CVE-2013-2445", "CVE-2013-2446", "CVE-2013-2447", "CVE-2013-2448", "CVE-2013-2450", "CVE-2013-2451", "CVE-2013-2452", "CVE-2013-2453", "CVE-2013-2455", "CVE-2013-2456", "CVE-2013-2457", "CVE-2013-2459", "CVE-2013-2461", "CVE-2013-2463", "CVE-2013-2465", "CVE-2013-2469", "CVE-2013-2470", "CVE-2013-2471", "CVE-2013-2472", "CVE-2013-2473");
  script_bugtraq_id(60617, 60618, 60619, 60620, 60623, 60625, 60627, 60629, 60632, 60633, 60634, 60638, 60639, 60640, 60641, 60644, 60645, 60646, 60647, 60651, 60653, 60655, 60656, 60657, 60658, 60659);
  script_xref(name:"DSA", value:"2727");

  script_name(english:"Debian DSA-2727-1 : openjdk-6 - several vulnerabilities");
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
    value:"http://www.debian.org/security/2013/dsa-2727"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the openjdk-6 packages.

For the oldstable distribution (squeeze), these problems have been
fixed in version 6b27-1.12.6-1~deb6u1.

For the stable distribution (wheezy), these problems have been fixed
in version 6b27-1.12.6-1~deb7u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java storeImageArray() Invalid Array Indexing Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openjdk-6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/28");
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
if (deb_check(release:"6.0", prefix:"icedtea-6-jre-cacao", reference:"6b27-1.12.6-1~deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"openjdk-6-dbg", reference:"6b27-1.12.6-1~deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"openjdk-6-demo", reference:"6b27-1.12.6-1~deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"openjdk-6-doc", reference:"6b27-1.12.6-1~deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"openjdk-6-jdk", reference:"6b27-1.12.6-1~deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"openjdk-6-jre", reference:"6b27-1.12.6-1~deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"openjdk-6-jre-headless", reference:"6b27-1.12.6-1~deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"openjdk-6-jre-lib", reference:"6b27-1.12.6-1~deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"openjdk-6-jre-zero", reference:"6b27-1.12.6-1~deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"openjdk-6-source", reference:"6b27-1.12.6-1~deb6u1")) flag++;
if (deb_check(release:"7.0", prefix:"icedtea-6-jre-cacao", reference:"6b27-1.12.6-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"icedtea-6-jre-jamvm", reference:"6b27-1.12.6-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"openjdk-6-dbg", reference:"6b27-1.12.6-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"openjdk-6-demo", reference:"6b27-1.12.6-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"openjdk-6-doc", reference:"6b27-1.12.6-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"openjdk-6-jdk", reference:"6b27-1.12.6-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"openjdk-6-jre", reference:"6b27-1.12.6-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"openjdk-6-jre-headless", reference:"6b27-1.12.6-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"openjdk-6-jre-lib", reference:"6b27-1.12.6-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"openjdk-6-jre-zero", reference:"6b27-1.12.6-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"openjdk-6-source", reference:"6b27-1.12.6-1~deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
