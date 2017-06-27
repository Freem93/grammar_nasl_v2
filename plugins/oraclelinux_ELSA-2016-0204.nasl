#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2016:0204 and 
# Oracle Linux Security Advisory ELSA-2016-0204 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(88782);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/12/07 21:08:16 $");

  script_cve_id("CVE-2016-0741");
  script_osvdb_id(133531);
  script_xref(name:"RHSA", value:"2016:0204");

  script_name(english:"Oracle Linux 7 : 389-ds-base (ELSA-2016-0204)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2016:0204 :

Updated 389-ds-base packages that fix one security issue and several
bugs are now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having Important
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The 389 Directory Server is an LDAP version 3 (LDAPv3) compliant
server. The base packages include the Lightweight Directory Access
Protocol (LDAP) server and command-line utilities for server
administration.

An infinite-loop vulnerability was discovered in the 389 directory
server, where the server failed to correctly handle unexpectedly
closed client connections. A remote attacker able to connect to the
server could use this flaw to make the directory server consume an
excessive amount of CPU and stop accepting connections (denial of
service). (CVE-2016-0741)

This update fixes the following bugs :

* Previously, if a simple paged results search failed in the back end,
the simple paged results slot was not released. Consequently, the
simple paged results slots in a connection object could be
accumulated. With this update, the simple paged results slot is
released correctly when a search fails, and unused simple paged
results slots are no longer left in a connection object. (BZ#1290725)

* Previously, when several values of the same attribute were deleted
using the ldapmodify command, and at least one of them was added again
during the same operation, the equality index was not updated. As a
consequence, an exact search for the re-added attribute value did not
return the entry. The logic of the index code has been modified to
update the index if at least one of the values in the entry changes,
and the exact search for the re-added attribute value now returns the
correct entry. (BZ#1290726)

* Prior to this update, when the cleanAllRUV task was running, a bogus
attrlist_replace error message was logged repeatedly due to a memory
corruption. With this update, the appropriate memory copy function
memmove is used, which fixes the memory corruption. As a result, the
error messages are no longer logged in this scenario. (BZ#1295684)

* To fix a simple paged results bug, an exclusive lock on a connection
was previously added. This consequently caused a self deadlock in a
particular case. With this update, the exclusive lock on a connection
has been changed to the re-entrant type, and the self deadlock no
longer occurs. (BZ#1298105)

* Previously, an unnecessary lock was sometimes acquired on a
connection object, which could consequently cause a deadlock. A patch
has been applied to remove the unnecessary locking, and the deadlock
no longer occurs. (BZ#1299346)

Users of 389-ds-base are advised to upgrade to these updated packages,
which correct these issues. After installing this update, the 389
server service will be restarted automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2016-February/005786.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected 389-ds-base packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:389-ds-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:389-ds-base-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:389-ds-base-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"389-ds-base-1.3.4.0-26.el7_2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"389-ds-base-devel-1.3.4.0-26.el7_2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"389-ds-base-libs-1.3.4.0-26.el7_2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "389-ds-base / 389-ds-base-devel / 389-ds-base-libs");
}
