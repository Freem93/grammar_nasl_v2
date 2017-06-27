#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0975 and 
# CentOS Errata and Security Advisory 2011:0975 respectively.
#

include("compat.inc");

if (description)
{
  script_id(56260);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/04 14:39:51 $");

  script_cve_id("CVE-2010-4341");
  script_bugtraq_id(45961);
  script_xref(name:"RHSA", value:"2011:0975");

  script_name(english:"CentOS 5 : sssd (CESA-2011:0975)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated sssd packages that fix one security issue, several bugs, and
add various enhancements are now available for Red Hat Enterprise
Linux 5.

The Red Hat Security Response Team has rated this update as having low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The System Security Services Daemon (SSSD) provides a set of daemons
to manage access to remote directories and authentication mechanisms.
It provides an NSS and PAM interface toward the system and a pluggable
back-end system to connect to multiple different account sources. It
is also the basis to provide client auditing and policy services for
projects such as FreeIPA.

A flaw was found in the SSSD PAM responder that could allow a local
attacker to force SSSD to enter an infinite loop via a
carefully-crafted packet. With SSSD unresponsive, legitimate users
could be denied the ability to log in to the system. (CVE-2010-4341)

Red Hat would like to thank Sebastian Krahmer for reporting this
issue.

These updated sssd packages include a number of bug fixes and
enhancements. Space precludes documenting all of these changes in this
advisory. Refer to the Red Hat Enterprise Linux 5.7 Technical Notes
for information about these changes :

https://docs.redhat.com/docs/en-US/Red_Hat_Enterprise_Linux/5/html/
5.7_Technical_Notes/sssd.html#RHSA-2011-0975

All sssd users are advised to upgrade to these updated sssd packages,
which upgrade SSSD to upstream version 1.5.1 to correct this issue,
and fix the bugs and add the enhancements noted in the Technical
Notes."
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-September/017982.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?16c2637d"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-September/017983.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ae3a297a"
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2011-September/000150.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?524cb8ae"
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2011-September/000151.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c4df99ac"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected sssd packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sssd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sssd-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sssd-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/23");
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
if (rpm_check(release:"CentOS-5", reference:"sssd-1.5.1-37.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"sssd-client-1.5.1-37.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"sssd-tools-1.5.1-37.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
