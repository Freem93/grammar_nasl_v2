#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2161. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51977);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/05/12 14:46:29 $");

  script_cve_id("CVE-2010-4476");
  script_bugtraq_id(46091);
  script_osvdb_id(70965);
  script_xref(name:"DSA", value:"2161");

  script_name(english:"Debian DSA-2161-1 : openjdk-6 - denial of service");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that the floating point parser in OpenJDK, an
implementation of the Java platform, can enter an infinite loop when
processing certain input strings. Such input strings represent valid
numbers and can be contained in data supplied by an attacker over the
network, leading to a denial-of-service attack."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=612660"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/openjdk-6"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2161"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the openjdk-6 packages.

For the oldstable distribution (lenny), this problem will be fixed in
version 6b18-1.8.3-2~lenny1. For technical reasons, this update will
be released separately.

For the stable distribution (squeeze), this problem has been fixed in
version 6b18-1.8.3-2+squeeze1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openjdk-6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"openjdk-6", reference:"6b18-1.8.3-2~lenny1")) flag++;
if (deb_check(release:"6.0", prefix:"icedtea-6-jre-cacao", reference:"6b18-1.8.3-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"openjdk-6-dbg", reference:"6b18-1.8.3-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"openjdk-6-demo", reference:"6b18-1.8.3-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"openjdk-6-doc", reference:"6b18-1.8.3-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"openjdk-6-jdk", reference:"6b18-1.8.3-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"openjdk-6-jre", reference:"6b18-1.8.3-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"openjdk-6-jre-headless", reference:"6b18-1.8.3-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"openjdk-6-jre-lib", reference:"6b18-1.8.3-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"openjdk-6-jre-zero", reference:"6b18-1.8.3-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"openjdk-6-source", reference:"6b18-1.8.3-2+squeeze1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
