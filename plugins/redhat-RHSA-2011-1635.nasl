#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1635. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57018);
  script_version ("$Revision: 1.10 $");
  script_cvs_date("$Date: 2017/01/04 16:12:16 $");

  script_cve_id("CVE-2011-2896");
  script_bugtraq_id(49148);
  script_osvdb_id(74539);
  script_xref(name:"RHSA", value:"2011:1635");

  script_name(english:"RHEL 6 : cups (RHSA-2011:1635)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated cups packages that fix one security issue and several bugs are
now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The Common UNIX Printing System (CUPS) provides a portable printing
layer for UNIX operating systems.

A heap-based buffer overflow flaw was found in the Lempel-Ziv-Welch
(LZW) decompression algorithm implementation used by the CUPS GIF
image format reader. An attacker could create a malicious GIF image
file that, when printed, could possibly cause CUPS to crash or,
potentially, execute arbitrary code with the privileges of the 'lp'
user. (CVE-2011-2896)

These updated cups packages also provide fixes for the following 
bugs :

* Previously CUPS was not correctly handling the language setting
LANG=en_US.ASCII. As a consequence lpadmin, lpstat and lpinfo binaries
were not displaying any output when the LANG=en_US.ASCII environment
variable was used. As a result of this update the problem is fixed and
the expected output is now displayed. (BZ#681836)

* Previously the scheduler did not check for empty values of several
configuration directives. As a consequence it was possible for the
CUPS daemon (cupsd) to crash when a configuration file contained
certain empty values. With this update the problem is fixed and cupsd
no longer crashes when reading such a configuration file. (BZ#706673)

* Previously when printing to a raw print queue, when using certain
printer models, CUPS was incorrectly sending SNMP queries. As a
consequence there was a noticeable 4-second delay between queueing the
job and the start of printing. With this update the problem is fixed
and CUPS no longer tries to collect SNMP supply and status information
for raw print queues. (BZ#709896)

* Previously when using the BrowsePoll directive it could happen that
the CUPS printer polling daemon (cups-polld) began polling before the
network interfaces were set up after a system boot. CUPS was then
caching the failed hostname lookup. As a consequence no printers were
found and the error, 'Host name lookup failure', was logged. With this
update the code that re-initializes the resolver after failure in
cups-polld is fixed and as a result CUPS will obtain the correct
network settings to use in printer discovery. (BZ#712430)

* The MaxJobs directive controls the maximum number of print jobs that
are kept in memory. Previously, once the number of jobs reached the
limit, the CUPS system failed to automatically purge the data file
associated with the oldest completed job from the system in order to
make room for a new print job. This bug has been fixed, and the jobs
beyond the set limit are now properly purged. (BZ#735505)

* The cups init script (/etc/rc.d/init.d/cups) uses the daemon
function (from /etc/rc.d/init.d/functions) to start the cups process,
but previously it did not source a configuration file from the
/etc/sysconfig/ directory. As a consequence, it was difficult to
cleanly set the nice level or cgroup for the cups daemon by setting
the NICELEVEL or CGROUP_DAEMON variables. With this update, the init
script is fixed. (BZ#744791)

All users of CUPS are advised to upgrade to these updated packages,
which contain backported patches to resolve these issues. After
installing this update, the cupsd daemon will be restarted
automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-2896.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2011-1635.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cups-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cups-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cups-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cups-lpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cups-php");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2011:1635";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"cups-1.4.2-44.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"cups-1.4.2-44.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"cups-1.4.2-44.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"cups-debuginfo-1.4.2-44.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"cups-devel-1.4.2-44.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"cups-libs-1.4.2-44.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"cups-lpd-1.4.2-44.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"cups-lpd-1.4.2-44.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"cups-lpd-1.4.2-44.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"cups-php-1.4.2-44.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"cups-php-1.4.2-44.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"cups-php-1.4.2-44.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cups / cups-debuginfo / cups-devel / cups-libs / cups-lpd / etc");
  }
}
