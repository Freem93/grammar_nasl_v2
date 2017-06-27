#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0753 and 
# CentOS Errata and Security Advisory 2013:0753 respectively.
#

include("compat.inc");

if (description)
{
  script_id(66003);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/04 14:39:52 $");

  script_cve_id("CVE-2013-1926", "CVE-2013-1927");
  script_bugtraq_id(59281, 59286);
  script_osvdb_id(92543, 92544);
  script_xref(name:"RHSA", value:"2013:0753");

  script_name(english:"CentOS 6 : icedtea-web (CESA-2013:0753)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated icedtea-web packages that fix two security issues are now
available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The IcedTea-Web project provides a Java web browser plug-in and an
implementation of Java Web Start, which is based on the Netx project.
It also contains a configuration tool for managing deployment settings
for the plug-in and Web Start implementations.

It was discovered that the IcedTea-Web plug-in incorrectly used the
same class loader instance for applets with the same value of the
codebase attribute, even when they originated from different domains.
A malicious applet could use this flaw to gain information about and
possibly manipulate applets from different domains currently running
in the browser. (CVE-2013-1926)

The IcedTea-Web plug-in did not properly check the format of the
downloaded Java Archive (JAR) files. This could cause the plug-in to
execute code hidden in a file in a different format, possibly allowing
attackers to execute code in the context of websites that allow
uploads of specific file types, known as a GIFAR attack.
(CVE-2013-1927)

The CVE-2013-1926 issue was discovered by Jiri Vanek of the Red Hat
OpenJDK Team, and CVE-2013-1927 was discovered by the Red Hat Security
Response Team.

This erratum also upgrades IcedTea-Web to version 1.2.3. Refer to the
NEWS file, linked to in the References, for further information.

All IcedTea-Web users should upgrade to these updated packages, which
resolve these issues. Web browsers using the IcedTea-Web browser
plug-in must be restarted for this update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2013-April/019694.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?461b2c84"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected icedtea-web packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:icedtea-web");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:icedtea-web-javadoc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"icedtea-web-1.2.3-2.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"icedtea-web-javadoc-1.2.3-2.el6_4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
