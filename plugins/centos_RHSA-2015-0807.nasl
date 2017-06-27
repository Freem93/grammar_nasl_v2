#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:0807 and 
# CentOS Errata and Security Advisory 2015:0807 respectively.
#

include("compat.inc");

if (description)
{
  script_id(82802);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/07/23 14:53:35 $");

  script_cve_id("CVE-2005-1080", "CVE-2015-0460", "CVE-2015-0469", "CVE-2015-0477", "CVE-2015-0478", "CVE-2015-0480", "CVE-2015-0488");
  script_osvdb_id(15435, 120703, 120709, 120710, 120712, 120713);
  script_xref(name:"RHSA", value:"2015:0807");

  script_name(english:"CentOS 5 : java-1.7.0-openjdk (CESA-2015:0807)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated java-1.7.0-openjdk packages that fix multiple security issues
are now available for Red Hat Enterprise Linux 5.

Red Hat Product Security has rated this update as having Important
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The java-1.7.0-openjdk packages provide the OpenJDK 7 Java Runtime
Environment and the OpenJDK 7 Java Software Development Kit.

An off-by-one flaw, leading to a buffer overflow, was found in the
font parsing code in the 2D component in OpenJDK. A specially crafted
font file could possibly cause the Java Virtual Machine to execute
arbitrary code, allowing an untrusted Java application or applet to
bypass Java sandbox restrictions. (CVE-2015-0469)

A flaw was found in the way the Hotspot component in OpenJDK handled
phantom references. An untrusted Java application or applet could use
this flaw to corrupt the Java Virtual Machine memory and, possibly,
execute arbitrary code, bypassing Java sandbox restrictions.
(CVE-2015-0460)

A flaw was found in the way the JSSE component in OpenJDK parsed X.509
certificate options. A specially crafted certificate could cause JSSE
to raise an exception, possibly causing an application using JSSE to
exit unexpectedly. (CVE-2015-0488)

A flaw was discovered in the Beans component in OpenJDK. An untrusted
Java application or applet could use this flaw to bypass certain Java
sandbox restrictions. (CVE-2015-0477)

A directory traversal flaw was found in the way the jar tool extracted
JAR archive files. A specially crafted JAR archive could cause jar to
overwrite arbitrary files writable by the user running jar when the
archive was extracted. (CVE-2005-1080, CVE-2015-0480)

It was found that the RSA implementation in the JCE component in
OpenJDK did not follow recommended practices for implementing RSA
signatures. (CVE-2015-0478)

The CVE-2015-0478 issue was discovered by Florian Weimer of Red Hat
Product Security.

All users of java-1.7.0-openjdk are advised to upgrade to these
updated packages, which resolve these issues. All running instances of
OpenJDK Java must be restarted for the update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2015-April/021075.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b2c8a4b5"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1.7.0-openjdk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:UR");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.7.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.7.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.7.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.7.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.7.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/16");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/04/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/CentOS/release")) audit(AUDIT_OS_NOT, "CentOS");
if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"java-1.7.0-openjdk-1.7.0.79-2.5.5.2.el5_11")) flag++;
if (rpm_check(release:"CentOS-5", reference:"java-1.7.0-openjdk-demo-1.7.0.79-2.5.5.2.el5_11")) flag++;
if (rpm_check(release:"CentOS-5", reference:"java-1.7.0-openjdk-devel-1.7.0.79-2.5.5.2.el5_11")) flag++;
if (rpm_check(release:"CentOS-5", reference:"java-1.7.0-openjdk-javadoc-1.7.0.79-2.5.5.2.el5_11")) flag++;
if (rpm_check(release:"CentOS-5", reference:"java-1.7.0-openjdk-src-1.7.0.79-2.5.5.2.el5_11")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
