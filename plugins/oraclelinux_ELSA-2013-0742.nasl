#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2013:0742 and 
# Oracle Linux Security Advisory ELSA-2013-0742 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(68806);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/06 17:02:15 $");

  script_cve_id("CVE-2013-1897");
  script_bugtraq_id(59026);
  script_xref(name:"RHSA", value:"2013:0742");

  script_name(english:"Oracle Linux 6 : 389-ds-base (ELSA-2013-0742)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2013:0742 :

Updated 389-ds-base packages that fix one security issue and several
bugs are now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The 389 Directory Server is an LDAPv3 compliant server. The base
packages include the Lightweight Directory Access Protocol (LDAP)
server and command-line utilities for server administration.

It was found that the 389 Directory Server did not properly restrict
access to entries when the 'nsslapd-allow-anonymous-access'
configuration setting was set to 'rootdse'. An anonymous user could
connect to the LDAP database and, if the search scope is set to BASE,
obtain access to information outside of the rootDSE. (CVE-2013-1897)

This issue was discovered by Martin Kosek of Red Hat.

This update also fixes the following bugs :

* Previously, the schema-reload plug-in was not thread-safe.
Consequently, executing the schema-reload.pl script under heavy load
could have caused the ns-slapd process to terminate unexpectedly with
a segmentation fault. Currently, the schema-reload plug-in is
re-designed so that it is thread-safe, and the schema-reload.pl script
can be executed along with other LDAP operations. (BZ#929107)

* An out of scope problem for a local variable, in some cases, caused
the modrdn operation to terminate unexpectedly with a segmentation
fault. This update declares the local variable at the proper place of
the function so it does not go out of scope, and the modrdn operation
no longer crashes. (BZ#929111)

* A task manually constructed an exact value to be removed from the
configuration if the 'replica-force-cleaning' option was used.
Consequently, the task configuration was not cleaned up, and every
time the server was restarted, the task behaved in the described
manner. This update searches the configuration for the exact value to
delete, instead of manually building the value, and the task does not
restart when the server is restarted. (BZ#929114)

* Previously, a NULL pointer dereference could have occurred when
attempting to get effective rights on an entry that did not exist,
leading to an unexpected termination due to a segmentation fault. This
update checks for NULL entry pointers and returns the appropriate
error. Now, attempts to get effective rights on an entry that does not
exist no longer causes crashes, and the server returns the appropriate
error message. (BZ#929115)

* A problem in the lock timing in the DNA plug-in caused a deadlock if
the DNA operation was executed with other plug-ins. This update moves
the release timing of the problematic lock, and the DNA plug-in does
not cause the deadlock. (BZ#929196)

All 389-ds-base users are advised to upgrade to these updated
packages, which contain backported patches to correct these issues.
After installing this update, the 389 server service will be restarted
automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2013-April/003411.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected 389-ds-base packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:389-ds-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:389-ds-base-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:389-ds-base-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"EL6", reference:"389-ds-base-1.2.11.15-14.el6_4")) flag++;
if (rpm_check(release:"EL6", reference:"389-ds-base-devel-1.2.11.15-14.el6_4")) flag++;
if (rpm_check(release:"EL6", reference:"389-ds-base-libs-1.2.11.15-14.el6_4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "389-ds-base / 389-ds-base-devel / 389-ds-base-libs");
}
