#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0589 and 
# CentOS Errata and Security Advisory 2013:0589 respectively.
#

include("compat.inc");

if (description)
{
  script_id(65160);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/11/12 17:08:53 $");

  script_cve_id("CVE-2013-0308");
  script_bugtraq_id(58148);
  script_osvdb_id(90610);
  script_xref(name:"RHSA", value:"2013:0589");

  script_name(english:"CentOS 6 : git (CESA-2013:0589)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated git packages that fix one security issue are now available for
Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

Git is a fast, scalable, distributed revision control system.

It was discovered that Git's git-imap-send command, a tool to send a
collection of patches from standard input (stdin) to an IMAP folder,
did not properly perform SSL X.509 v3 certificate validation on the
IMAP server's certificate, as it did not ensure that the server's
hostname matched the one provided in the CN field of the server's
certificate. A rogue server could use this flaw to conduct
man-in-the-middle attacks, possibly leading to the disclosure of
sensitive information. (CVE-2013-0308)

All git users should upgrade to these updated packages, which contain
a backported patch to correct this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2013-March/019618.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9d085139"
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2013-March/000818.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?710a8e2c"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected git packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:emacs-git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:emacs-git-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:git-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:git-cvs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:git-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:git-email");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:git-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:git-svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gitk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gitweb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perl-Git");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"emacs-git-1.7.1-3.el6_4.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"emacs-git-el-1.7.1-3.el6_4.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"git-1.7.1-3.el6_4.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"git-all-1.7.1-3.el6_4.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"git-cvs-1.7.1-3.el6_4.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"git-daemon-1.7.1-3.el6_4.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"git-email-1.7.1-3.el6_4.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"git-gui-1.7.1-3.el6_4.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"git-svn-1.7.1-3.el6_4.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"gitk-1.7.1-3.el6_4.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"gitweb-1.7.1-3.el6_4.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"perl-Git-1.7.1-3.el6_4.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
