#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0628. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65206);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2017/01/05 16:17:31 $");

  script_cve_id("CVE-2013-0312");
  script_bugtraq_id(58428);
  script_osvdb_id(91252);
  script_xref(name:"RHSA", value:"2013:0628");

  script_name(english:"RHEL 6 : 389-ds-base (RHSA-2013:0628)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated 389-ds-base packages that fix one security issue and multiple
bugs are now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

The 389 Directory Server is an LDAPv3 compliant server. The base
packages include the Lightweight Directory Access Protocol (LDAP)
server and command-line utilities for server administration.

A flaw was found in the way LDAPv3 control data was handled by 389
Directory Server. If a malicious user were able to bind to the
directory (even anonymously) and send an LDAP request containing
crafted LDAPv3 control data, they could cause the server to crash,
denying service to the directory. (CVE-2013-0312)

The CVE-2013-0312 issue was discovered by Thierry Bordaz of Red Hat.

This update also fixes the following bugs :

* After an upgrade from Red Hat Enterprise Linux 6.3 to version 6.4,
the upgrade script did not update the schema file for the PamConfig
object class. Consequently, new features for PAM such as configuration
of multiple instances and pamFilter attribute could not be used
because of the schema violation. With this update, the upgrade script
updates the schema file for the PamConfig object class and new
features function properly. (BZ#910994)

* Previously, the valgrind test suite reported recurring memory leaks
in the modify_update_last_modified_attr() function. The size of the
leaks averaged between 60-80 bytes per modify call. In environments
where modify operations were frequent, this caused significant
problems. Now, memory leaks no longer occur in the
modify_update_last_modified_attr() function. (BZ#910995)

* The Directory Server (DS) failed when multi-valued attributes were
replaced. The problem occurred when replication was enabled, while the
server executing the modification was configured as a single master
and there was at least one replication agreement. Consequently, the
modification requests were refused by the master server, which
returned a code 20 'Type or value exists' error message. These
requests were replacements of multi-valued attributes, and the error
only occurred when one of the new values matched one of the current
values of the attribute, but had a different letter case. Now,
modification requests function properly and no longer return code 20
errors. (BZ#910996)

* The DNA (distributed numeric assignment) plug-in, under certain
conditions, could log error messages with the 'DB_LOCK_DEADLOCK' error
code when attempting to create an entry with a uidNumber attribute.
Now, DNA handles this case properly and errors no longer occur during
attempts to create entries with uidNumber attributes. (BZ#911467)

* Posix Winsync plugin was calling an internal modify function which
was not necessary. The internal modify call failed and logged an error
message 'slapi_modify_internal_set_pb: NULL parameter' which was not
clear. This patch stops calling the internal modify function if it is
not necessary and the cryptic error message is not observed.
(BZ#911468)

* Previously, under certain conditions, the dse.ldif file had 0 bytes
after a server termination or when the machine was powered off.
Consequently, after the system was brought up, a DS or IdM system
could be unable to restart, leading to production server outages. Now,
the server mechanism by which the dse.ldif is written is more robust,
and tries all available backup dse.ldif files, and outages no longer
occur. (BZ#911469)

* Due to an incorrect interpretation of an error code, a directory
server considered an invalid chaining configuration setting as the
disk full error and shut down unexpectedly. Now, a more appropriate
error code is in use and the server no longer shuts down from invalid
chaining configuration settings. (BZ#911474)

* While trying to remove a tombstone entry, the ns-slapd daemon
terminated unexpectedly with a segmentation fault. With this update,
removal of tombstone entries no longer causes crashes. (BZ#914305)

All 389-ds-base users are advised to upgrade to these updated
packages, which contain backported patches to correct these issues.
After installing this update, the 389 server service will be restarted
automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-0312.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-0628.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:389-ds-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:389-ds-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:389-ds-base-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:389-ds-base-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2013:0628";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"389-ds-base-1.2.11.15-12.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"389-ds-base-1.2.11.15-12.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"389-ds-base-debuginfo-1.2.11.15-12.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"389-ds-base-debuginfo-1.2.11.15-12.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"389-ds-base-devel-1.2.11.15-12.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"389-ds-base-devel-1.2.11.15-12.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"389-ds-base-libs-1.2.11.15-12.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"389-ds-base-libs-1.2.11.15-12.el6_4")) flag++;


  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "389-ds-base / 389-ds-base-debuginfo / 389-ds-base-devel / etc");
  }
}
