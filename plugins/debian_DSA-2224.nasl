#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2224. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(53507);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/05/19 17:45:43 $");

  script_cve_id("CVE-2010-4351", "CVE-2010-4448", "CVE-2010-4450", "CVE-2010-4465", "CVE-2010-4469", "CVE-2010-4470", "CVE-2010-4471", "CVE-2010-4472", "CVE-2011-0025", "CVE-2011-0706");
  script_bugtraq_id(45894, 46110, 46387, 46397, 46398, 46399, 46400, 46404, 46406, 46439);
  script_osvdb_id(71620, 71621, 73765);
  script_xref(name:"DSA", value:"2224");

  script_name(english:"Debian DSA-2224-1 : openjdk-6 - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several security vulnerabilities were discovered in OpenJDK, an
implementation of the Java platform.

  - CVE-2010-4351
    The JNLP SecurityManager returns from the
    checkPermission method instead of throwing an exception
    in certain circumstances, which might allow
    context-dependent attackers to bypass the intended
    security policy by creating instances of ClassLoader.

  - CVE-2010-4448
    Malicious applets can perform DNS cache poisoning.

  - CVE-2010-4450
    An empty (but set) LD_LIBRARY_PATH environment variable
    results in a misconstructed library search path,
    resulting in code execution from possibly untrusted
    sources.

  - CVE-2010-4465
    Malicious applets can extend their privileges by abusing
    Swing timers.

  - CVE-2010-4469
    The Hotspot just-in-time compiler miscompiles crafted
    byte sequences, resulting in heap corruption.

  - CVE-2010-4470
    JAXP can be exploited by untrusted code to elevate
    privileges.

  - CVE-2010-4471
    Java2D can be exploited by untrusted code to elevate
    privileges.

  - CVE-2010-4472
    Untrusted code can replace the XML DSIG implementation.

  - CVE-2011-0025
    Signatures on JAR files are not properly verified, which
    allows remote attackers to trick users into executing
    code that appears to come from a trusted source.

  - CVE-2011-0706
    The JNLPClassLoader class allows remote attackers to
    gain privileges via unknown vectors related to multiple
    signers and the assignment of an inappropriate security
    descriptor.

In addition, this security update contains stability fixes, such as
switching to the recommended Hotspot version (hs14) for this
particular version of OpenJDK."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-4351"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-4448"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-4450"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-4465"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-4469"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-4470"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-4471"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-4472"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-0025"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-0706"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/openjdk-6"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2224"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the openjdk-6 packages.

For the oldstable distribution (lenny), these problems have been fixed
in version 6b18-1.8.7-2~lenny1.

For the stable distribution (squeeze), these problems have been fixed
in version 6b18-1.8.7-2~squeeze1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openjdk-6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/21");
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
if (deb_check(release:"5.0", prefix:"openjdk-6", reference:"6b18-1.8.7-2~lenny1")) flag++;
if (deb_check(release:"6.0", prefix:"icedtea-6-jre-cacao", reference:"6b18-1.8.7-2~squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"openjdk-6-dbg", reference:"6b18-1.8.7-2~squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"openjdk-6-demo", reference:"6b18-1.8.7-2~squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"openjdk-6-doc", reference:"6b18-1.8.7-2~squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"openjdk-6-jdk", reference:"6b18-1.8.7-2~squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"openjdk-6-jre", reference:"6b18-1.8.7-2~squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"openjdk-6-jre-headless", reference:"6b18-1.8.7-2~squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"openjdk-6-jre-lib", reference:"6b18-1.8.7-2~squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"openjdk-6-jre-zero", reference:"6b18-1.8.7-2~squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"openjdk-6-source", reference:"6b18-1.8.7-2~squeeze1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
