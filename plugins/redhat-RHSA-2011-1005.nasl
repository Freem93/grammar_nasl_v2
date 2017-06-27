#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1005. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55644);
  script_version ("$Revision: 1.9 $");
  script_cvs_date("$Date: 2017/01/04 16:02:22 $");

  script_cve_id("CVE-2007-3852");
  script_bugtraq_id(25380);
  script_xref(name:"RHSA", value:"2011:1005");

  script_name(english:"RHEL 5 : sysstat (RHSA-2011:1005)");
  script_summary(english:"Checks the rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated sysstat package that fixes one security issue, various
bugs, and adds one enhancement is now available for Red Hat Enterprise
Linux 5.

The Red Hat Security Response Team has rated this update as having low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The sysstat package contains a set of utilities which enable system
monitoring of disks, network, and other I/O activity.

It was found that the sysstat initscript created a temporary file in
an insecure way. A local attacker could use this flaw to create
arbitrary files via a symbolic link attack. (CVE-2007-3852)

This update fixes the following bugs :

* On systems under heavy load, the sadc utility would sometimes output
the following error message if a write() call was unable to write all
of the requested input :

'Cannot write data to system activity file: Success.'

In this updated package, the sadc utility tries to write the remaining
input, resolving this issue. (BZ#454617)

* On the Itanium architecture, the 'sar -I' command provided incorrect
information about the interrupt statistics of the system. With this
update, the 'sar -I' command has been disabled for this architecture,
preventing this bug. (BZ#468340)

* Previously, the 'iostat -n' command used invalid data to create
statistics for read and write operations. With this update, the data
source for these statistics has been fixed, and the iostat utility now
returns correct information. (BZ#484439)

* The 'sar -d' command used to output invalid data about block
devices. With this update, the sar utility recognizes disk
registration and disk overflow statistics properly, and only correct
and relevant data is now displayed. (BZ#517490)

* Previously, the sar utility set the maximum number of days to be
logged in one month too high. Consequently, data from a month was
appended to data from the preceding month. With this update, the
maximum number of days has been set to 25, and data from a month now
correctly replaces data from the preceding month. (BZ#578929)

* In previous versions of the iostat utility, the number of NFS mount
points was hard-coded. Consequently, various issues occurred while
iostat was running and NFS mount points were mounted or unmounted;
certain values in iostat reports overflowed and some mount points were
not reported at all. With this update, iostat properly recognizes when
an NFS mount point mounts or unmounts, fixing these issues.
(BZ#675058, BZ#706095, BZ#694767)

* When a device name was longer than 13 characters, the iostat utility
printed a redundant new line character, making its output less
readable. This bug has been fixed and now, no extra characters are
printed if a long device name occurs in iostat output. (BZ#604637)

* Previously, if kernel interrupt counters overflowed, the sar utility
provided confusing output. This bug has been fixed and the sum of
interrupts is now reported correctly. (BZ#622557)

* When some processors were disabled on a multi-processor system, the
sar utility sometimes failed to provide information about the CPU
activity. With this update, the uptime of a single processor is used
to compute the statistics, rather than the total uptime of all
processors, and this bug no longer occurs. (BZ#630559)

* Previously, the mpstat utility wrongly interpreted data about
processors in the system. Consequently, it reported a processor that
did not exist. This bug has been fixed and non-existent CPUs are no
longer reported by mpstat. (BZ#579409)

* Previously, there was no easy way to enable the collection of
statistics about disks and interrupts. Now, the SADC_OPTIONS variable
can be used to set parameters for the sadc utility, fixing this bug.
(BZ#598794)

* The read_uptime() function failed to close its open file upon exit.
A patch has been provided to fix this bug. (BZ#696672)

This update also adds the following enhancement :

* With this update, the cifsiostat utility has been added to the
sysstat package to provide CIFS (Common Internet File System) mount
point I/O statistics. (BZ#591530)

All sysstat users are advised to upgrade to this updated package,
which contains backported patches to correct these issues and add this
enhancement."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-3852.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2011-1005.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected sysstat package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sysstat");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/22");
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
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2011:1005";
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
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"sysstat-7.0.2-11.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"sysstat-7.0.2-11.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"sysstat-7.0.2-11.el5")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "sysstat");
  }
}
