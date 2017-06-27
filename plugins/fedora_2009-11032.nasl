#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2009-11032.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(42400);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2016/12/08 20:21:54 $");

  script_cve_id("CVE-2009-3547", "CVE-2009-3621", "CVE-2009-3624", "CVE-2009-3638");
  script_bugtraq_id(36723, 36793, 36803, 36901);
  script_xref(name:"FEDORA", value:"2009-11032");

  script_name(english:"Fedora 11 : kernel-2.6.30.9-96.fc11 (2009-11032)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Tue Nov 3 2009 Kyle McMartin <kyle at redhat.com>
    2.6.30.9-96

    - fs/pipe.c: fix NULL pointer dereference
      (CVE-2009-3547)

    - Sun Oct 25 2009 Chuck Ebbert <cebbert at redhat.com>
      2.6.30.9-95

    - Disable the stack protector on functions that don't
      have onstack arrays.

    - Thu Oct 22 2009 Chuck Ebbert <cebbert at redhat.com>
      2.6.30.9-94

    - Fix overflow in KVM cpuid code. (CVE-2009-3638)

    - Thu Oct 22 2009 Chuck Ebbert <cebbert at redhat.com>
      2.6.30.9-93

    - Fix exploitable oops in keyring code (CVE-2009-3624)

    - Wed Oct 21 2009 Kyle McMartin <kyle at redhat.com>

    - shut-up-LOCK_TEST_WITH_RETURN.patch: sort out
      #445331... or paper bag over it for now until the lock
      warnings can be killed.

  - Mon Oct 19 2009 Kyle McMartin <kyle at redhat.com>

    -
      af_unix-fix-deadlock-connecting-to-shutdown-socket.pat
      ch: fix for rhbz#529626 local DoS. (CVE-2009-3621)

  - Sat Oct 17 2009 Chuck Ebbert <cebbert at redhat.com>
    2.6.30.9-90

    - Fix null deref in r128 (F10#487546) (CVE-2009-3620)

    - Sat Oct 17 2009 Chuck Ebbert <cebbert at redhat.com>
      2.6.30.9-89

    - Keyboard and mouse fixes from 2.6.32 (#522126)

    - Sat Oct 17 2009 Chuck Ebbert <cebbert at redhat.com>
      2.6.30.9-88

    - Scheduler wakeup patch, fixes high latency on wakeup
      (sched-update-the-clock-of-runqueue-select-task-rq-sel
      ected.patch)

  - Fri Oct 16 2009 Chuck Ebbert <cebbert at redhat.com>
    2.6.30.9-87

    - Fix uninitialized data leak in netlink (CVE-2009-3612)

    - Thu Oct 15 2009 Chuck Ebbert <cebbert at redhat.com>
      2.6.30.9-86

    - AX.25 security fix (CVE-2009-2909)

    - Thu Oct 15 2009 Chuck Ebbert <cebbert at redhat.com>
      2.6.30.9-85

    - Disable CONFIG_USB_STORAGE_CYPRESS_ATACB because it
      causes failure to boot from USB disks using Cypress
      bridges (#524998)

  - Tue Oct 13 2009 Chuck Ebbert <cebbert at redhat.com>
    2.6.30.9-84

    - Copy libata drive detection fix from 2.6.31.4
      (#524756)

    - Tue Oct 13 2009 Chuck Ebbert <cebbert at redhat.com>
      2.6.30.9-83

    - Networking fixes taken from 2.6.31-stable

    - Tue Oct 13 2009 Chuck Ebbert <cebbert at redhat.com>
      2.6.30.9-82

    - Fix boot hang with ACPI on some systems.

    - Mon Oct 12 2009 Chuck Ebbert <cebbert at redhat.com>
      2.6.30.9-81

    - Critical ftrace fixes:
      ftrace-use-module-notifier-for-function-tracer.patch
      ftrace-check-for-failure-for-all-conversions.patch
      tracing-correct-module-boundaries-for-ftrace_release.p
      atch

  - Thu Oct 8 2009 Ben Skeggs <bskeggs at redhat.com>
    2.6.30.9-80

    - ppc: compile nvidiafb as a module only,
      nvidiafb+nouveau = bang! (rh#491308)

    - Wed Oct 7 2009 Dave Jones <davej at redhat.com>
      2.6.30.9-78

    - Disable IRQSOFF tracer. (Adds unnecessary overhead
      when unused)

    - Wed Oct 7 2009 Chuck Ebbert <cebbert at redhat.com>
      2.6.30.9-77

    - eCryptfs fixes taken from 2.6.31.2 (fixes
      CVE-2009-2908)

    - Tue Oct 6 2009 Chuck Ebbert <cebbert at redhat.com>
      2.6.30.9-76

    - fix race in forcedeth network driver (#526546)

    - Tue Oct 6 2009 Chuck Ebbert <cebbert at redhat.com>
      2.6.30.9-75

    - x86: Don't leak 64-bit reg contents to 32-bit tasks.

    - Tue Oct 6 2009 Chuck Ebbert <cebbert at redhat.com>
      2.6.30.9-74

[plus 194 lines in the Changelog]

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=529626"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=530283"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=530490"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=530515"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-November/030674.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2c4aae2b"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(189, 310, 362);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = eregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! ereg(pattern:"^11([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 11.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC11", reference:"kernel-2.6.30.9-96.fc11")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
