#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2507. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59839);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/05/05 14:58:42 $");

  script_cve_id("CVE-2012-1711", "CVE-2012-1713", "CVE-2012-1716", "CVE-2012-1717", "CVE-2012-1718", "CVE-2012-1719", "CVE-2012-1723", "CVE-2012-1724", "CVE-2012-1725");
  script_bugtraq_id(53946, 53947, 53949, 53950, 53951, 53952, 53954, 53958, 53960);
  script_osvdb_id(82874, 82877, 82878, 82879, 82880, 82882, 82883, 82884, 82886);
  script_xref(name:"DSA", value:"2507");

  script_name(english:"Debian DSA-2507-1 : openjdk-6 - several vulnerabilities");
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

  - CVE-2012-1711 CVE-2012-1719
    Multiple errors in the CORBA implementation could lead
    to breakouts of the Java sandbox.

  - CVE-2012-1713
    Missing input sanitising in the font manager could lead
    to the execution of arbitrary code.

  - CVE-2012-1716
    The SynthLookAndFeel Swing class could be abused to
    break out of the Java sandbox.

  - CVE-2012-1717
    Several temporary files were created insecurely,
    resulting in local information disclosure.

  - CVE-2012-1718
    Certificate revocation lists were incorrectly
    implemented.

  - CVE-2012-1723 CVE-2012-1725
    Validation errors in the bytecode verifier of the
    Hotspot VM could lead to breakouts of the Java sandbox.

  - CVE-2012-1724
    Missing input sanitising in the XML parser could lead to
    denial of service through an infinite loop."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-1711"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-1719"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-1713"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-1716"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-1717"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-1718"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-1723"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-1725"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-1724"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/openjdk-6"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2012/dsa-2507"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the openjdk-6 packages.

For the stable distribution (squeeze), this problem has been fixed in
version 6b18-1.8.13-0+squeeze2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java Applet Field Bytecode Verifier Cache Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openjdk-6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/05");
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
if (deb_check(release:"6.0", prefix:"icedtea-6-jre-cacao", reference:"6b18-1.8.13-0+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"openjdk-6-dbg", reference:"6b18-1.8.13-0+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"openjdk-6-demo", reference:"6b18-1.8.13-0+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"openjdk-6-doc", reference:"6b18-1.8.13-0+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"openjdk-6-jdk", reference:"6b18-1.8.13-0+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"openjdk-6-jre", reference:"6b18-1.8.13-0+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"openjdk-6-jre-headless", reference:"6b18-1.8.13-0+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"openjdk-6-jre-lib", reference:"6b18-1.8.13-0+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"openjdk-6-jre-zero", reference:"6b18-1.8.13-0+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"openjdk-6-source", reference:"6b18-1.8.13-0+squeeze2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
