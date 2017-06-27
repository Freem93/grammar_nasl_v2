#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1769. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(36142);
  script_version("$Revision: 1.23 $");
  script_cvs_date("$Date: 2016/12/06 20:12:51 $");

  script_cve_id("CVE-2006-2426", "CVE-2009-0581", "CVE-2009-0723", "CVE-2009-0733", "CVE-2009-0793", "CVE-2009-1093", "CVE-2009-1094", "CVE-2009-1095", "CVE-2009-1096", "CVE-2009-1097", "CVE-2009-1098", "CVE-2009-1101");
  script_bugtraq_id(34185, 34240, 34411);
  script_osvdb_id(56307, 56308, 56310);
  script_xref(name:"DSA", value:"1769");

  script_name(english:"Debian DSA-1769-1 : openjdk-6 - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been identified in OpenJDK, an
implementation of the Java SE platform.

  - CVE-2006-2426
    Creation of large, temporary fonts could use up
    available disk space, leading to a denial of service
    condition.

  - CVE-2009-0581 / CVE-2009-0723 / CVE-2009-0733 /
    CVE-2009-0793

    Several vulnerabilities existed in the embedded
    LittleCMS library, exploitable through crafted images: a
    memory leak, resulting in a denial of service condition
    (CVE-2009-0581 ), heap-based buffer overflows,
    potentially allowing arbitrary code execution
    (CVE-2009-0723, CVE-2009-0733 ), and a NULL pointer
    dereference, leading to denial of service (CVE-2009-0793
    ).

  - CVE-2009-1093
    The LDAP server implementation (in com.sun.jdni.ldap)
    did not properly close sockets if an error was
    encountered, leading to a denial-of-service condition.

  - CVE-2009-1094
    The LDAP client implementation (in com.sun.jdni.ldap)
    allowed malicious LDAP servers to execute arbitrary code
    on the client.

  - CVE-2009-1101
    The HTTP server implementation (sun.net.httpserver)
    contained an unspecified denial of service
    vulnerability.

  - CVE-2009-1095 / CVE-2009-1096 / CVE-2009-1097 /
    CVE-2009-1098

    Several issues in Java Web Start have been addressed.
    The Debian packages currently do not support Java Web
    Start, so these issues are not directly exploitable, but
    the relevant code has been updated nevertheless."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-2426"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0581"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0723"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0733"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0793"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0581"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0723"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0733"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0793"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1093"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1094"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1101"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1095"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1096"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1097"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1098"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1769"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the openjdk-6 packages.

For the stable distribution (lenny), these problems have been fixed in
version 9.1+lenny2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(16, 20, 119, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openjdk-6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"openjdk-6-dbg", reference:"6b11-9.1+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"openjdk-6-demo", reference:"6b11-9.1+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"openjdk-6-doc", reference:"6b11-9.1+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"openjdk-6-jdk", reference:"6b11-9.1+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"openjdk-6-jre", reference:"6b11-9.1+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"openjdk-6-jre-headless", reference:"6b11-9.1+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"openjdk-6-jre-lib", reference:"6b11-9.1+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"openjdk-6-source", reference:"6b11-9.1+lenny2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
