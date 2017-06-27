#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0281 and 
# CentOS Errata and Security Advisory 2011:0281 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(53421);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/20 13:54:05 $");

  script_cve_id("CVE-2010-4448", "CVE-2010-4450", "CVE-2010-4465", "CVE-2010-4469", "CVE-2010-4470", "CVE-2010-4472");
  script_bugtraq_id(46387, 46397, 46398, 46400, 46404, 46406);
  script_xref(name:"RHSA", value:"2011:0281");

  script_name(english:"CentOS 5 : java-1.6.0-openjdk (CESA-2011:0281)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated java-1.6.0-openjdk packages that fix several security issues
are now available for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

These packages provide the OpenJDK 6 Java Runtime Environment and the
OpenJDK 6 Software Development Kit.

A flaw was found in the Swing library. Forged TimerEvents could be
used to bypass SecurityManager checks, allowing access to otherwise
blocked files and directories. (CVE-2010-4465)

A flaw was found in the HotSpot component in OpenJDK. Certain bytecode
instructions confused the memory management within the Java Virtual
Machine (JVM), which could lead to heap corruption. (CVE-2010-4469)

A flaw was found in the way JAXP (Java API for XML Processing)
components were handled, allowing them to be manipulated by untrusted
applets. This could be used to elevate privileges and bypass secure
XML processing restrictions. (CVE-2010-4470)

It was found that untrusted applets could create and place cache
entries in the name resolution cache. This could allow an attacker
targeted manipulation over name resolution until the OpenJDK VM is
restarted. (CVE-2010-4448)

It was found that the Java launcher provided by OpenJDK did not check
the LD_LIBRARY_PATH environment variable for insecure empty path
elements. A local attacker able to trick a user into running the Java
launcher while working from an attacker-writable directory could use
this flaw to load an untrusted library, subverting the Java security
model. (CVE-2010-4450)

A flaw was found in the XML Digital Signature component in OpenJDK.
Untrusted code could use this flaw to replace the Java Runtime
Environment (JRE) XML Digital Signature Transform or C14N algorithm
implementations to intercept digital signature operations.
(CVE-2010-4472)

Note: All of the above flaws can only be remotely triggered in OpenJDK
by calling the 'appletviewer' application.

This update also provides one defense in depth patch. (BZ#676019)

All users of java-1.6.0-openjdk are advised to upgrade to these
updated packages, which resolve these issues. All running instances of
OpenJDK Java must be restarted for the update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-April/017313.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3c4f061b"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-April/017314.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?df6bc49a"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1.6.0-openjdk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

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
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"java-1.6.0-openjdk-1.6.0.0-1.20.b17.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"java-1.6.0-openjdk-demo-1.6.0.0-1.20.b17.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"java-1.6.0-openjdk-devel-1.6.0.0-1.20.b17.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"java-1.6.0-openjdk-javadoc-1.6.0.0-1.20.b17.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"java-1.6.0-openjdk-src-1.6.0.0-1.20.b17.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
