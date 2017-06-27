#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0663 and 
# CentOS Errata and Security Advisory 2013:0663 respectively.
#

include("compat.inc");

if (description)
{
  script_id(65634);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2013/06/29 00:03:04 $");

  script_cve_id("CVE-2013-0287");
  script_osvdb_id(91519);
  script_xref(name:"RHSA", value:"2013:0663");

  script_name(english:"CentOS 6 : sssd (CESA-2013:0663)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated sssd packages that fix one security issue and two bugs are now
available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

SSSD (System Security Services Daemon) provides a set of daemons to
manage access to remote directories and authentication mechanisms. It
provides NSS (Name Service Switch) and PAM (Pluggable Authentication
Modules) interfaces toward the system and a pluggable back end system
to connect to multiple different account sources.

When SSSD was configured as a Microsoft Active Directory client by
using the new Active Directory provider (introduced in
RHSA-2013:0508), the Simple Access Provider ('access_provider =
simple' in '/etc/sssd/sssd.conf') did not handle access control
correctly. If any groups were specified with the 'simple_deny_groups'
option (in sssd.conf), all users were permitted access.
(CVE-2013-0287)

The CVE-2013-0287 issue was discovered by Kaushik Banerjee of Red Hat.

This update also fixes the following bugs :

* If a group contained a member whose Distinguished Name (DN) pointed
out of any of the configured search bases, the search request that was
processing this particular group never ran to completion. To the user,
this bug manifested as a long timeout between requesting the group
data and receiving the result. A patch has been provided to address
this bug and SSSD now processes group search requests without delays.
(BZ#907362)

* The pwd_expiration_warning should have been set for seven days, but
instead it was set to zero for Kerberos. This incorrect zero setting
returned the 'always display warning if the server sends one' error
message and users experienced problems in environments like IPA or
Active Directory. Currently, the value setting for Kerberos is
modified and this issue no longer occurs. (BZ#914671)

All users of sssd are advised to upgrade to these updated packages,
which contain backported patches to correct these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2013-March/019657.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4afb10e1"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected sssd packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:N");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"libipa_hbac-1.9.2-82.4.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libipa_hbac-devel-1.9.2-82.4.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libipa_hbac-python-1.9.2-82.4.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libsss_autofs-1.9.2-82.4.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libsss_idmap-1.9.2-82.4.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libsss_idmap-devel-1.9.2-82.4.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libsss_sudo-1.9.2-82.4.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libsss_sudo-devel-1.9.2-82.4.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"sssd-1.9.2-82.4.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"sssd-client-1.9.2-82.4.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"sssd-tools-1.9.2-82.4.el6_4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
