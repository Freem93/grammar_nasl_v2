#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2356. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56987);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2016/05/19 17:45:43 $");

  script_cve_id("CVE-2011-3389", "CVE-2011-3521", "CVE-2011-3544", "CVE-2011-3547", "CVE-2011-3548", "CVE-2011-3551", "CVE-2011-3552", "CVE-2011-3553", "CVE-2011-3554", "CVE-2011-3556", "CVE-2011-3557", "CVE-2011-3560");
  script_bugtraq_id(49388, 49778, 50211, 50215, 50216, 50218, 50224, 50231, 50234, 50236, 50243, 50246, 50248);
  script_osvdb_id(74829, 76495, 76496, 76497, 76498, 76500, 76502, 76505, 76506, 76507, 76511, 76512);
  script_xref(name:"DSA", value:"2356");

  script_name(english:"Debian DSA-2356-1 : openjdk-6 - several vulnerabilities (BEAST)");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in OpenJDK, an
implementation of the Java platform :

  - CVE-2011-3389
    The TLS implementation does not guard properly against
    certain chosen-plaintext attacks when block ciphers are
    used in CBC mode.

  - CVE-2011-3521
    The CORBA implementation contains a deserialization
    vulnerability in the IIOP implementation, allowing
    untrusted Java code (such as applets) to elevate its
    privileges.

  - CVE-2011-3544
    The Java scripting engine lacks necessary security
    manager checks, allowing untrusted Java code (such as
    applets) to elevate its privileges.

  - CVE-2011-3547
    The skip() method in java.io.InputStream uses a shared
    buffer, allowing untrusted Java code (such as applets)
    to access data that is skipped by other code.

  - CVE-2011-3548
    The java.awt.AWTKeyStroke class contains a flaw which
    allows untrusted Java code (such as applets) to elevate
    its privileges.

  - CVE-2011-3551
    The Java2D C code contains an integer overflow which
    results in a heap-based buffer overflow, potentially
    allowing untrusted Java code (such as applets) to
    elevate its privileges.

  - CVE-2011-3552
    Malicous Java code can use up an excessive amount of UDP
    ports, leading to a denial of service.

  - CVE-2011-3553
    JAX-WS enables stack traces for certain server responses
    by default, potentially leaking sensitive information.

  - CVE-2011-3554
    JAR files in pack200 format are not properly checked for
    errors, potentially leading to arbitrary code execution
    when unpacking crafted pack200 files.

  - CVE-2011-3556
    The RMI Registry server lacks access restrictions on
    certain methods, allowing a remote client to execute
    arbitary code.

  - CVE-2011-3557
    The RMI Registry server fails to properly restrict
    privileges of untrusted Java code, allowing RMI clients
    to elevate their privileges on the RMI Registry server.

  - CVE-2011-3560
    The com.sun.net.ssl.HttpsURLConnection class does not
    perform proper security manager checks in the
    setSSLSocketFactory() method, allowing untrusted Java
    code to bypass security policy restrictions."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-3389"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-3521"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-3544"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-3547"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-3548"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-3551"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-3552"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-3553"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-3554"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-3556"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-3557"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-3560"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/openjdk-6"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2356"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the openjdk-6 packages.

For the stable distribution (squeeze), this problem has been fixed in
version 6b18-1.8.10-0+squeeze2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java Applet Rhino Script Engine Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openjdk-6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/01");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/02");
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
if (deb_check(release:"6.0", prefix:"icedtea-6-jre-cacao", reference:"6b18-1.8.10-0+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"openjdk-6-dbg", reference:"6b18-1.8.10-0+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"openjdk-6-demo", reference:"6b18-1.8.10-0+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"openjdk-6-doc", reference:"6b18-1.8.10-0+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"openjdk-6-jdk", reference:"6b18-1.8.10-0+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"openjdk-6-jre", reference:"6b18-1.8.10-0+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"openjdk-6-jre-headless", reference:"6b18-1.8.10-0+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"openjdk-6-jre-lib", reference:"6b18-1.8.10-0+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"openjdk-6-jre-zero", reference:"6b18-1.8.10-0+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"openjdk-6-source", reference:"6b18-1.8.10-0+squeeze2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
