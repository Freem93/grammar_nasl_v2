#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0300. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(32424);
  script_version ("$Revision: 1.18 $");
  script_cvs_date("$Date: 2017/01/03 17:16:33 $");

  script_cve_id("CVE-2007-6283", "CVE-2008-0122");
  script_bugtraq_id(27283);
  script_osvdb_id(40811, 42655);
  script_xref(name:"RHSA", value:"2008:0300");

  script_name(english:"RHEL 5 : bind (RHSA-2008:0300)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated bind packages that fix two security issues, several bugs, and
add enhancements are now available for Red Hat Enterprise Linux 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The Berkeley Internet Name Domain (BIND) is an implementation of the
Domain Name System (DNS) protocols. BIND includes a DNS server
(named); a resolver library (routines for applications to use when
interfacing with DNS); and tools for verifying that the DNS server is
operating correctly.

It was discovered that the bind packages created the 'rndc.key' file
with insecure file permissions. This allowed any local user to read
the content of this file. A local user could use this flaw to control
some aspects of the named daemon by using the rndc utility, for
example, stopping the named daemon. This problem did not affect
systems with the bind-chroot package installed. (CVE-2007-6283)

A buffer overflow flaw was discovered in the 'inet_network()'
function, as implemented by libbind. An attacker could use this flaw
to crash an application calling this function, with an argument
provided from an untrusted source. (CVE-2008-0122)

As well, these updated packages fix the following bugs :

* when using an LDAP backend, missing function declarations caused
segmentation faults, due to stripped pointers on machines where
pointers are longer than integers.

* starting named may have resulted in named crashing, due to a race
condition during D-BUS connection initialization. This has been
resolved in these updated packages.

* the named init script returned incorrect error codes, causing the
'status' command to return an incorrect status. In these updated
packages, the named init script is Linux Standard Base (LSB)
compliant.

* in these updated packages, the 'rndc [command] [zone]' command,
where [command] is an rndc command, and [zone] is the specified zone,
will find the [zone] if the zone is unique to all views.

* the default named log rotation script did not work correctly when
using the bind-chroot package. In these updated packages, installing
bind-chroot creates the symbolic link '/var/log/named.log', which
points to '/var/named/chroot/var/log/named.log', which resolves this
issue.

* a previous bind update incorrectly changed the permissions on the
'/etc/openldap/schema/dnszone.schema' file to mode 640, instead of
mode 644, which resulted in OpenLDAP not being able to start. In these
updated packages, the permissions are correctly set to mode 644.

* the 'checkconfig' parameter was missing in the named usage report.
For example, running the 'service named' command did not return
'checkconfig' in the list of available options.

* due to a bug in the named init script not handling the rndc return
value correctly, the 'service named stop' and 'service named restart'
commands failed on certain systems.

* the bind-chroot spec file printed errors when running the '%pre' and
'%post' sections. Errors such as the following occurred :

Locating //etc/named.conf failed: [FAILED]

This has been resolved in these updated packages.

* installing the bind-chroot package creates a '/dev/random' file in
the chroot environment; however, the '/dev/random' file had an
incorrect SELinux label. Starting named resulted in an 'avc: denied {
getattr } for pid=[pid] comm='named' path='/dev/random'' error being
logged. The '/dev/random' file has the correct SELinux label in these
updated packages.

* in certain situations, running the 'bind +trace' command resulted in
random segmentation faults.

As well, these updated packages add the following enhancements :

* support has been added for GSS-TSIG (RFC 3645).

* the 'named.root' file has been updated to reflect the new address
for L.ROOT-SERVERS.NET.

* updates BIND to the latest 9.3 maintenance release.

All users of bind are advised to upgrade to these updated packages,
which resolve these issues and add these enhancements."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-6283.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-0122.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2008-0300.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189, 200);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-chroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-libbind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-sdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:caching-nameserver");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/05/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/05/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2008:0300";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
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
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"bind-9.3.4-6.P1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"bind-9.3.4-6.P1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"bind-9.3.4-6.P1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"bind-chroot-9.3.4-6.P1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"bind-chroot-9.3.4-6.P1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"bind-chroot-9.3.4-6.P1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"bind-devel-9.3.4-6.P1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"bind-libbind-devel-9.3.4-6.P1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"bind-libs-9.3.4-6.P1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"bind-sdb-9.3.4-6.P1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"bind-sdb-9.3.4-6.P1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"bind-sdb-9.3.4-6.P1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"bind-utils-9.3.4-6.P1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"bind-utils-9.3.4-6.P1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"bind-utils-9.3.4-6.P1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"caching-nameserver-9.3.4-6.P1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"caching-nameserver-9.3.4-6.P1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"caching-nameserver-9.3.4-6.P1.el5")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bind / bind-chroot / bind-devel / bind-libbind-devel / bind-libs / etc");
  }
}
