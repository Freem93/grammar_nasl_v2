#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0508 and 
# CentOS Errata and Security Advisory 2013:0508 respectively.
#

include("compat.inc");

if (description)
{
  script_id(65142);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/05/19 23:52:01 $");

  script_cve_id("CVE-2013-0219", "CVE-2013-0220");
  script_bugtraq_id(57539);
  script_osvdb_id(89540, 89541, 89542);
  script_xref(name:"RHSA", value:"2013:0508");

  script_name(english:"CentOS 6 : sssd (CESA-2013:0508)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated sssd packages that fix two security issues, multiple bugs, and
add various enhancements are now available for Red Hat Enterprise
Linux 6.

The Red Hat Security Response Team has rated this update as having low
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The System Security Services Daemon (SSSD) provides a set of daemons
to manage access to remote directories and authentication mechanisms.
It provides an NSS and PAM interface toward the system and a pluggable
back-end system to connect to multiple different account sources. It
is also the basis to provide client auditing and policy services for
projects such as FreeIPA.

A race condition was found in the way SSSD copied and removed user
home directories. A local attacker who is able to write into the home
directory of a different user who is being removed could use this flaw
to perform symbolic link attacks, possibly allowing them to modify and
delete arbitrary files with the privileges of the root user.
(CVE-2013-0219)

Multiple out-of-bounds memory read flaws were found in the way the
autofs and SSH service responders parsed certain SSSD packets. An
attacker could spend a specially crafted packet that, when processed
by the autofs or SSH service responders, would cause SSSD to crash.
This issue only caused a temporary denial of service, as SSSD was
automatically restarted by the monitor process after the crash.
(CVE-2013-0220)

The CVE-2013-0219 and CVE-2013-0220 issues were discovered by Florian
Weimer of the Red Hat Product Security Team.

These updated sssd packages also include numerous bug fixes and
enhancements. Space precludes documenting all of these changes in this
advisory. Users are directed to the Red Hat Enterprise Linux 6.4
Technical Notes, linked to in the References, for information on the
most significant of these changes.

All SSSD users are advised to upgrade to these updated packages, which
upgrade SSSD to upstream version 1.9 to correct these issues, fix
these bugs and add these enhancements."
  );
  # http://lists.centos.org/pipermail/centos-announce/2013-March/019515.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1baaa6b4"
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2013-February/000707.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dcc828a0"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected sssd packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libipa_hbac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libipa_hbac-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libipa_hbac-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libsss_autofs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libsss_idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libsss_idmap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libsss_sudo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libsss_sudo-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sssd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sssd-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sssd-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"libipa_hbac-1.9.2-82.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libipa_hbac-devel-1.9.2-82.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libipa_hbac-python-1.9.2-82.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libsss_autofs-1.9.2-82.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libsss_idmap-1.9.2-82.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libsss_idmap-devel-1.9.2-82.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libsss_sudo-1.9.2-82.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libsss_sudo-devel-1.9.2-82.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"sssd-1.9.2-82.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"sssd-client-1.9.2-82.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"sssd-tools-1.9.2-82.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
