#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2420. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58148);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2016/05/19 17:45:44 $");

  script_cve_id("CVE-2011-3377", "CVE-2011-3563", "CVE-2011-5035", "CVE-2012-0497", "CVE-2012-0501", "CVE-2012-0502", "CVE-2012-0503", "CVE-2012-0505", "CVE-2012-0506", "CVE-2012-0507");
  script_bugtraq_id(50610, 51194, 52009, 52011, 52012, 52013, 52014, 52017, 52018, 52161);
  script_osvdb_id(76940, 78114, 78413, 79228, 79229, 79230, 79232, 79233, 79235, 79236);
  script_xref(name:"DSA", value:"2420");

  script_name(english:"Debian DSA-2420-1 : openjdk-6 - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in OpenJDK, an
implementation of the Oracle Java platform.

  - CVE-2011-3377
    The IcedTea browser plugin included in the openjdk-6
    package does not properly enforce the Same Origin Policy
    on web content served under a domain name which has a
    common suffix with the required domain name.

  - CVE-2011-3563
    The Java Sound component did not properly check for
    array boundaries. A malicious input or an untrusted Java
    application or applet could use this flaw to cause Java
    Virtual Machine to crash or disclose portion of its
    memory.

  - CVE-2011-5035
    The OpenJDK embedded web server did not guard against an
    excessive number of a request parameters, leading to a
    denial of service vulnerability involving hash
    collisions.

  - CVE-2012-0497
    It was discovered that Java2D did not properly check
    graphics rendering objects before passing them to the
    native renderer. This could lead to JVM crash or Java
    sandbox bypass.

  - CVE-2012-0501
    The ZIP central directory parser used by
    java.util.zip.ZipFile entered an infinite recursion in
    native code when processing a crafted ZIP file, leading
    to a denial of service.

  - CVE-2012-0502
    A flaw was found in the AWT KeyboardFocusManager class
    that could allow untrusted Java applets to acquire
    keyboard focus and possibly steal sensitive information.

  - CVE-2012-0503
    The java.util.TimeZone.setDefault() method lacked a
    security manager invocation, allowing an untrusted Java
    application or applet to set a new default time zone.

  - CVE-2012-0505
    The Java serialization code leaked references to
    serialization exceptions, possibly leaking critical
    objects to untrusted code in Java applets and
    applications.

  - CVE-2012-0506
    It was discovered that CORBA implementation in Java did
    not properly protect repository identifiers (that can be
    obtained using _ids() method) on certain Corba objects.
    This could have been used to perform modification of the
    data that should have been immutable.

  - CVE-2012-0507
    The AtomicReferenceArray class implementation did not
    properly check if the array is of an expected Object[]
    type. A malicious Java application or applet could use
    this flaw to cause Java Virtual Machine to crash or
    bypass Java sandbox restrictions."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-3377"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-3563"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-5035"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-0497"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-0501"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-0502"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-0503"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-0505"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-0506"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-0507"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/openjdk-6"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2012/dsa-2420"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the openjdk-6 packages.

For the stable distribution (squeeze), these problems have been fixed
in version 6b18-1.8.13-0+squeeze1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java AtomicReferenceArray Type Violation Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openjdk-6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"icedtea-6-jre-cacao", reference:"6b18-1.8.13-0+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"openjdk-6-dbg", reference:"6b18-1.8.13-0+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"openjdk-6-demo", reference:"6b18-1.8.13-0+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"openjdk-6-doc", reference:"6b18-1.8.13-0+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"openjdk-6-jdk", reference:"6b18-1.8.13-0+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"openjdk-6-jre", reference:"6b18-1.8.13-0+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"openjdk-6-jre-headless", reference:"6b18-1.8.13-0+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"openjdk-6-jre-lib", reference:"6b18-1.8.13-0+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"openjdk-6-jre-zero", reference:"6b18-1.8.13-0+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"openjdk-6-source", reference:"6b18-1.8.13-0+squeeze1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
