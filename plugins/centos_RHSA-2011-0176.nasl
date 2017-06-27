#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0176 and 
# CentOS Errata and Security Advisory 2011:0176 respectively.
#

include("compat.inc");

if (description)
{
  script_id(53415);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/07/01 13:30:47 $");

  script_cve_id("CVE-2010-3860", "CVE-2010-4351");
  script_bugtraq_id(45114, 45894);
  script_xref(name:"RHSA", value:"2011:0176");

  script_name(english:"CentOS 5 : java-1.6.0-openjdk (CESA-2011:0176)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated java-1.6.0-openjdk packages that fix two security issues are
now available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

These packages provide the OpenJDK 6 Java Runtime Environment and the
OpenJDK 6 Software Development Kit. The javaws command can be used to
launch Java Web Start applications.

A public static field declaration allowed untrusted JNLP (Java Network
Launching Protocol) applications to read privileged data. A remote
attacker could directly or indirectly read the values of restricted
system properties, such as 'user.name', 'user.home', and 'java.home',
which untrusted applications should not be allowed to read.
(CVE-2010-3860)

It was found that JNLPSecurityManager could silently return without
throwing an exception when permission was denied. If the javaws
command was used to launch a Java Web Start application that relies on
this exception being thrown, it could result in that application being
run with elevated privileges, allowing it to bypass security manager
restrictions and gain access to privileged functionality.
(CVE-2010-4351)

Note: The RHSA-2010:0339 java-1.6.0-openjdk update installed javaws by
mistake. As part of the fixes for CVE-2010-3860 and CVE-2010-4351,
this update removes javaws.

Red Hat would like to thank the TippingPoint Zero Day Initiative
project for reporting CVE-2010-4351. The original issue reporter
wishes to stay anonymous.

This erratum also upgrades the OpenJDK package to IcedTea6 1.7.7.
Refer to the NEWS file, linked to in the References, for further
information.

All users of java-1.6.0-openjdk are advised to upgrade to these
updated packages, which resolve these issues. All running instances of
OpenJDK Java must be restarted for the update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-April/017309.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5e4daf09"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-April/017310.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a1de9a3d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1.6.0-openjdk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.6.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.6.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.6.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.6.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.6.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"java-1.6.0-openjdk-1.6.0.0-1.17.b17.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"java-1.6.0-openjdk-demo-1.6.0.0-1.17.b17.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"java-1.6.0-openjdk-devel-1.6.0.0-1.17.b17.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"java-1.6.0-openjdk-javadoc-1.6.0.0-1.17.b17.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"java-1.6.0-openjdk-src-1.6.0.0-1.17.b17.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
