#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200407-16.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(14549);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/04/13 13:34:22 $");

  script_cve_id("CVE-2004-0447", "CVE-2004-0496", "CVE-2004-0497", "CVE-2004-0565");
  script_xref(name:"GLSA", value:"200407-16");

  script_name(english:"GLSA-200407-16 : Linux Kernel: Multiple DoS and permission vulnerabilities");
  script_summary(english:"Checks for updated package(s) in /var/db/pkg");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Gentoo host is missing one or more security-related
patches."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote host is affected by the vulnerability described in GLSA-200407-16
(Linux Kernel: Multiple DoS and permission vulnerabilities)

    The Linux kernel allows a local attacker to mount a remote file system
    on a vulnerable Linux host and modify files' group IDs. On 2.4 series
    kernels this vulnerability only affects shared NFS file systems. This
    vulnerability has been assigned CAN-2004-0497 by the Common
    Vulnerabilities and Exposures project.
    Also, a flaw in the handling of /proc attributes has been found in 2.6
    series kernels; allowing the unauthorized modification of /proc
    entries, especially those which rely solely on file permissions for
    security to vital kernel parameters.
    An issue specific to the VServer Linux sources has been found, by which
    /proc related changes in one virtual context are applied to other
    contexts as well, including the host system.
    CAN-2004-0447 resolves a local DoS vulnerability on IA64 platforms
    which can cause unknown behaviour and CAN-2004-0565 resolves a floating
    point information leak on IA64 platforms by which registers of other
    processes can be read by a local user.
    Finally, CAN-2004-0496 addresses some more unknown vulnerabilities in
    2.6 series Linux kernels older than 2.6.7 which were found by the
    Sparse source code checking tool.
  
Impact :

    Bad Group IDs can possibly cause a Denial of Service on parts of a host
    if the changed files normally require a special GID to properly
    operate. By exploiting this vulnerability, users in the original file
    group would also be blocked from accessing the changed files.
    The /proc attribute vulnerability allows local users with previously no
    permissions to certain /proc entries to exploit the vulnerability and
    then gain read, write and execute access to entries.
    These new privileges can be used to cause unknown behaviour ranging
    from reduced system performance to a Denial of Service by manipulating
    various kernel options which are usually reserved for the superuser.
    This flaw might also be used for opening restrictions set through /proc
    entries, allowing further attacks to take place through another
    possibly unexpected attack vector.
    The VServer issue can also be used to induce similar unexpected
    behaviour to other VServer contexts, including the host. By successful
    exploitation, a Denial of Service for other contexts can be caused
    allowing only root to read certain /proc entries. Such a change would
    also be replicated to other contexts, forbidding normal users on those
    contexts to read /proc entries which could contain details needed by
    daemons running as a non-root user, for example.
    Additionally, this vulnerability allows an attacker to read information
    from another context, possibly hosting a different server, gaining
    critical information such as what processes are running. This may be
    used for furthering the exploitation of either context.
    CAN-2004-0447 and CAN-2004-0496 permit various local unknown Denial of
    Service vulnerabilities with unknown impacts - these vulnerabilities
    can be used to possibly elevate privileges or access reserved kernel
    memory which can be used for further exploitation of the system.
    CAN-2004-0565 allows FPU register values of other processes to be read
    by a local user setting the MFH bit during a floating point operation -
    since no check was in place to ensure that the FPH bit was owned by the
    requesting process, but only an MFH bit check, an attacker can simply
    set the MFH bit and access FPU registers of processes running as other
    users, possibly those running as root.
  
Workaround :

    2.4 users may not be affected by CAN-2004-0497 if they do not use
    remote network filesystems and do not have support for any such
    filesystems in their kernel configuration. All 2.6 users are affected
    by the /proc attribute issue and the only known workaround is to
    disable /proc support. The VServer flaw applies only to
    vserver-sources, and no workaround is currently known for the issue.
    There is no known fix to CAN-2004-0447, CAN-2004-0496 or CAN-2004-0565
    other than to upgrade the kernel to a patched version.
    As a result, all users affected by any of these vulnerabilities should
    upgrade their kernels to ensure the integrity of their systems."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.securityfocus.com/archive/1/367977"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200407-16"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Users are encouraged to upgrade to the latest available sources for
    their system:
    # emerge sync
    # emerge -pv your-favorite-sources
    # emerge your-favorite-sources
    # # Follow usual procedure for compiling and installing a kernel.
    # # If you use genkernel, run genkernel as you would do normally."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:aa-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:alpha-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:ck-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:compaq-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:development-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:gentoo-dev-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:gentoo-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:grsec-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:gs-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:hardened-dev-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:hardened-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:hppa-dev-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:hppa-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:ia64-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mips-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mm-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:openmosix-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:pac-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:pegasos-dev-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:pegasos-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:planet-ccrma-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:ppc-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:rsbac-dev-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:rsbac-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:selinux-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:sparc-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:uclinux-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:usermode-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:vanilla-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:vserver-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:win4lin-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:wolk-sources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:xbox-sources");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
  script_family(english:"Gentoo Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("qpkg.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Gentoo/release")) audit(AUDIT_OS_NOT, "Gentoo");
if (!get_kb_item("Host/Gentoo/qpkg-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;

if (qpkg_check(package:"sys-kernel/rsbac-sources", unaffected:make_list("ge 2.4.26-r3"), vulnerable:make_list("lt 2.4.26-r3"))) flag++;
if (qpkg_check(package:"sys-kernel/hppa-dev-sources", unaffected:make_list("ge 2.6.7_p1-r2"), vulnerable:make_list("lt 2.6.7_p1-r2"))) flag++;
if (qpkg_check(package:"sys-kernel/hppa-sources", unaffected:make_list("ge 2.4.26_p6-r1"), vulnerable:make_list("lt 2.4.26_p6-r1"))) flag++;
if (qpkg_check(package:"sys-kernel/planet-ccrma-sources", unaffected:make_list("ge 2.4.21-r11"), vulnerable:make_list("lt 2.4.21-r11"))) flag++;
if (qpkg_check(package:"sys-kernel/openmosix-sources", unaffected:make_list("ge 2.4.22-r11"), vulnerable:make_list("lt 2.4.22-r11"))) flag++;
if (qpkg_check(package:"sys-kernel/vserver-sources", unaffected:make_list("ge 2.0"), vulnerable:make_list("lt 2.4.26.1.28-r1", "ge 2.4", "lt 2.0"))) flag++;
if (qpkg_check(package:"sys-kernel/development-sources", unaffected:make_list("ge 2.6.8_rc1"), vulnerable:make_list("lt 2.6.8_rc1"))) flag++;
if (qpkg_check(package:"sys-kernel/xbox-sources", unaffected:make_list("rge 2.4.26-r3", "ge 2.6.7-r2"), vulnerable:make_list("lt 2.6.7-r2"))) flag++;
if (qpkg_check(package:"sys-kernel/hardened-dev-sources", unaffected:make_list("ge 2.6.7-r2"), vulnerable:make_list("lt 2.6.7-r2"))) flag++;
if (qpkg_check(package:"sys-kernel/gentoo-dev-sources", unaffected:make_list("ge 2.6.7-r8"), vulnerable:make_list("lt 2.6.7-r8"))) flag++;
if (qpkg_check(package:"sys-kernel/mips-sources", unaffected:make_list("ge 2.4.27"), vulnerable:make_list("lt 2.4.27"))) flag++;
if (qpkg_check(package:"sys-kernel/compaq-sources", unaffected:make_list("ge 2.4.9.32.7-r8"), vulnerable:make_list("lt 2.4.9.32.7-r8"))) flag++;
if (qpkg_check(package:"sys-kernel/pegasos-sources", unaffected:make_list("ge 2.4.26-r3"), vulnerable:make_list("lt 2.4.26-r3"))) flag++;
if (qpkg_check(package:"sys-kernel/grsec-sources", unaffected:make_list("ge 2.4.26.2.0-r6"), vulnerable:make_list("lt 2.4.26.2.0-r6"))) flag++;
if (qpkg_check(package:"sys-kernel/uclinux-sources", unaffected:make_list("rge 2.4.26_p0-r3", "ge 2.6.7_p0-r2"), vulnerable:make_list("lt 2.6.7_p0-r2"))) flag++;
if (qpkg_check(package:"sys-kernel/wolk-sources", unaffected:make_list("rge 4.9-r10", "rge 4.11-r7", "ge 4.14-r4"), vulnerable:make_list("lt 4.14-r4"))) flag++;
if (qpkg_check(package:"sys-kernel/vanilla-sources", unaffected:make_list("ge 2.4.27"), vulnerable:make_list("le 2.4.26"))) flag++;
if (qpkg_check(package:"sys-kernel/gentoo-sources", unaffected:make_list("rge 2.4.19-r18", "rge 2.4.20-r21", "rge 2.4.22-r13", "rge 2.4.25-r6", "ge 2.4.26-r5"), vulnerable:make_list("lt 2.4.26-r5"))) flag++;
if (qpkg_check(package:"sys-kernel/hardened-sources", unaffected:make_list("ge 2.4.26-r3"), vulnerable:make_list("lt 2.4.26-r3"))) flag++;
if (qpkg_check(package:"sys-kernel/aa-sources", unaffected:make_list("rge 2.4.23-r2", "ge 2.6.5-r5"), vulnerable:make_list("lt 2.6.5-r5"))) flag++;
if (qpkg_check(package:"sys-kernel/gs-sources", unaffected:make_list("ge 2.4.25_pre7-r8"), vulnerable:make_list("lt 2.4.25_pre7-r8"))) flag++;
if (qpkg_check(package:"sys-kernel/ia64-sources", unaffected:make_list("ge 2.4.24-r7"), vulnerable:make_list("lt 2.4.24-r7"))) flag++;
if (qpkg_check(package:"sys-kernel/pegasos-dev-sources", unaffected:make_list("ge 2.6.7-r2"), vulnerable:make_list("lt 2.6.7-r2"))) flag++;
if (qpkg_check(package:"sys-kernel/pac-sources", unaffected:make_list("ge 2.4.23-r9"), vulnerable:make_list("lt 2.4.23-r9"))) flag++;
if (qpkg_check(package:"sys-kernel/sparc-sources", unaffected:make_list("ge 2.4.26-r3"), vulnerable:make_list("lt 2.4.26-r3"))) flag++;
if (qpkg_check(package:"sys-kernel/alpha-sources", unaffected:make_list("ge 2.4.21-r9"), vulnerable:make_list("lt 2.4.21-r9"))) flag++;
if (qpkg_check(package:"sys-kernel/ppc-sources", unaffected:make_list("ge 2.4.26-r3"), vulnerable:make_list("lt 2.4.26-r3"))) flag++;
if (qpkg_check(package:"sys-kernel/rsbac-dev-sources", unaffected:make_list("ge 2.6.7-r2"), vulnerable:make_list("lt 2.6.7-r2"))) flag++;
if (qpkg_check(package:"sys-kernel/selinux-sources", unaffected:make_list("ge 2.4.26-r2"), vulnerable:make_list("lt 2.4.26-r2"))) flag++;
if (qpkg_check(package:"sys-kernel/usermode-sources", unaffected:make_list("rge 2.4.24-r6", "rge 2.4.26-r3", "ge 2.6.6-r4"), vulnerable:make_list("lt 2.6.6-r4"))) flag++;
if (qpkg_check(package:"sys-kernel/ck-sources", unaffected:make_list("rge 2.4.26-r1", "ge 2.6.7-r5"), vulnerable:make_list("lt 2.6.7-r5"))) flag++;
if (qpkg_check(package:"sys-kernel/win4lin-sources", unaffected:make_list("rge 2.4.26-r3", "ge 2.6.7-r2"), vulnerable:make_list("lt 2.6.7-r2"))) flag++;
if (qpkg_check(package:"sys-kernel/mm-sources", unaffected:make_list("ge 2.6.7-r6"), vulnerable:make_list("lt 2.6.7-r6"))) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:qpkg_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Linux Kernel");
}
