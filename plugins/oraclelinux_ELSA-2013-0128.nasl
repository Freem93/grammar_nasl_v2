#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2013:0128 and 
# Oracle Linux Security Advisory ELSA-2013-0128 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(68699);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/12/01 17:16:03 $");

  script_cve_id("CVE-2012-3359", "CVE-2013-7347");
  script_osvdb_id(89877, 105135);
  script_xref(name:"RHSA", value:"2013:0128");

  script_name(english:"Oracle Linux 5 : conga (ELSA-2013-0128)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2013:0128 :

Updated conga packages that fix one security issue, multiple bugs, and
add two enhancements are now available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The Conga project is a management system for remote workstations. It
consists of luci, which is a secure web-based front end, and ricci,
which is a secure daemon that dispatches incoming messages to
underlying management modules.

It was discovered that luci stored usernames and passwords in session
cookies. This issue prevented the session inactivity timeout feature
from working correctly, and allowed attackers able to get access to a
session cookie to obtain the victim's authentication credentials.
(CVE-2012-3359)

Red Hat would like to thank George Hedfors of Cybercom Sweden East AB
for reporting this issue.

This update also fixes the following bugs :

* Prior to this update, luci did not allow the fence_apc_snmp agent to
be configured. As a consequence, users could not configure or view an
existing configuration for fence_apc_snmp. This update adds a new
screen that allows fence_apc_snmp to be configured. (BZ#832181)

* Prior to this update, luci did not allow the SSL operation of the
fence_ilo fence agent to be enabled or disabled. As a consequence,
users could not configure or view an existing configuration for the
'ssl' attribute for fence_ilo. This update adds a checkbox to show
whether the SSL operation is enabled and allows users to edit that
attribute. (BZ#832183)

* Prior to this update, luci did not allow the 'identity_file'
attribute of the fence_ilo_mp fence agent to be viewed or edited. As a
consequence, users could not configure or view an existing
configuration for the 'identity_file' attribute of the fence_ilo_mp
fence agent. This update adds a text input box to show the current
state of the 'identity_file' attribute of fence_ilo_mp and allows
users to edit that attribute. (BZ#832185)

* Prior to this update, redundant files and directories remained on
the file system at /var/lib/luci/var/pts and
/usr/lib{,64}/luci/zope/var/pts when the luci package was uninstalled.
This update removes these files and directories when the luci package
is uninstalled. (BZ#835649)

* Prior to this update, the 'restart-disable' recovery policy was not
displayed in the recovery policy list from which users could select
when they configure a recovery policy for a failover domain. As a
consequence, the 'restart-disable' recovery policy could not be set
with the luci GUI. This update adds the 'restart-disable' recovery
option to the recovery policy pulldown list. (BZ#839732)

* Prior to this update, line breaks that were not anticipated in the
'yum list' output could cause package upgrade and/or installation to
fail when creating clusters or adding nodes to existing clusters. As a
consequence, creating clusters and adding cluster nodes to existing
clusters could fail. This update modifies the ricci daemon to be able
to correctly handle line breaks in the 'yum list' output. (BZ#842865)

In addition, this update adds the following enhancements :

* This update adds support for configuring the Intel iPDU fence agent
to the luci package. (BZ#741986)

* This update adds support for viewing and changing the state of the
new 'nfsrestart' attribute to the FS and Cluster FS resource agent
configuration screens. (BZ#822633)

All users of conga are advised to upgrade to these updated packages,
which resolve these issues and add these enhancements. After
installing this update, the luci and ricci services will be restarted
automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2013-January/003200.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected conga packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:luci");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ricci");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 5", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL5", reference:"luci-0.12.2-64.0.2.el5")) flag++;
if (rpm_check(release:"EL5", reference:"ricci-0.12.2-64.0.2.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "luci / ricci");
}
