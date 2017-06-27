#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2016:2765 and 
# Oracle Linux Security Advisory ELSA-2016-2765 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(94907);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/11/18 14:29:48 $");

  script_cve_id("CVE-2016-4992", "CVE-2016-5405", "CVE-2016-5416");
  script_osvdb_id(140221, 142287, 146339);
  script_xref(name:"RHSA", value:"2016:2765");

  script_name(english:"Oracle Linux 6 : 389-ds-base (ELSA-2016-2765)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2016:2765 :

An update for 389-ds-base is now available for Red Hat Enterprise
Linux 6.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

389 Directory Server is an LDAP version 3 (LDAPv3) compliant server.
The base packages include the Lightweight Directory Access Protocol
(LDAP) server and command-line utilities for server administration.

Security Fix(es) :

* It was found that 389 Directory Server was vulnerable to a flaw in
which the default ACI (Access Control Instructions) could be read by
an anonymous user. This could lead to leakage of sensitive
information. (CVE-2016-5416)

* An information disclosure flaw was found in 389 Directory Server. A
user with no access to objects in certain LDAP sub-tree could send
LDAP ADD operations with a specific object name. The error message
returned to the user was different based on whether the target object
existed or not. (CVE-2016-4992)

* It was found that 389 Directory Server was vulnerable to a remote
password disclosure via timing attack. A remote attacker could
possibly use this flaw to retrieve directory server password after
many tries. (CVE-2016-5405)

The CVE-2016-5416 issue was discovered by Viktor Ashirov (Red Hat);
the CVE-2016-4992 issue was discovered by Petr Spacek (Red Hat) and
Martin Basti (Red Hat); and the CVE-2016-5405 issue was discovered by
William Brown (Red Hat).

Bug Fix(es) :

* Previously, a bug in the changelog iterator buffer caused it to
point to an incorrect position when reloading the buffer. This caused
replication to skip parts of the changelog, and consequently some
changes were not replicated. This bug has been fixed, and replication
data loss due to an incorrectly reloaded changelog buffer no longer
occurs. (BZ#1354331)

* Previously, if internal modifications were generated on a consumer
(for example by the Account Policy plug-in) and additional changes to
the same attributes were received from replication, a bug caused
Directory Server to accumulate state information on the consumer. The
bug has been fixed by making sure that replace operations are only
applied if they are newer than existing attribute deletion change
sequence numbers (CSNs), and state information no longer accumulates
in this situation. (BZ#1379599)

Enhancement(s) :

* In a multi-master replication environment where multiple masters
receive updates at the same time, it was previously possible for a
single master to obtain exclusive access to a replica and hold it for
a very long time due to problems such as a slow network connection.
During this time, other masters were blocked from accessing the same
replica, which considerably slowed down the replication process. This
update adds a new configuration attribute,
'nsds5ReplicaReleaseTimeout', which can be used to specify a timeout
in seconds. After the specified timeout period passes, the master
releases the replica, allowing other masters to access it and send
their updates. (BZ#1358390)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2016-November/006511.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected 389-ds-base packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:389-ds-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:389-ds-base-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:389-ds-base-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/16");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL6", reference:"389-ds-base-1.2.11.15-84.el6_8")) flag++;
if (rpm_check(release:"EL6", reference:"389-ds-base-devel-1.2.11.15-84.el6_8")) flag++;
if (rpm_check(release:"EL6", reference:"389-ds-base-libs-1.2.11.15-84.el6_8")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "389-ds-base / 389-ds-base-devel / 389-ds-base-libs");
}
