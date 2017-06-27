#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2012:0152 and 
# Oracle Linux Security Advisory ELSA-2012-0152 respectively.
#

include("compat.inc");

if (description)
{
  script_id(68470);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/12/01 17:07:15 $");

  script_cve_id("CVE-2011-3588", "CVE-2011-3589", "CVE-2011-3590");
  script_bugtraq_id(50415, 50416, 50420);
  script_xref(name:"RHSA", value:"2012:0152");

  script_name(english:"Oracle Linux 5 : kexec-tools (ELSA-2012-0152)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2012:0152 :

An updated kexec-tools package that resolves three security issues,
fixes several bugs and adds various enhancements is now available for
Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The kexec-tools package contains the /sbin/kexec binary and utilities
that together form the user-space component of the kernel's kexec
feature. The /sbin/kexec binary facilitates a new kernel to boot using
the kernel's kexec feature either on a normal or a panic reboot. The
kexec fastboot mechanism allows booting a Linux kernel from the
context of an already running kernel.

Kdump used the SSH (Secure Shell) 'StrictHostKeyChecking=no' option
when dumping to SSH targets, causing the target kdump server's SSH
host key not to be checked. This could make it easier for a
man-in-the-middle attacker on the local network to impersonate the
kdump SSH target server and possibly gain access to sensitive
information in the vmcore dumps. (CVE-2011-3588)

The mkdumprd utility created initrd files with world-readable
permissions. A local user could possibly use this flaw to gain access
to sensitive information, such as the private SSH key used to
authenticate to a remote server when kdump was configured to dump to
an SSH target. (CVE-2011-3589)

The mkdumprd utility included unneeded sensitive files (such as all
files from the '/root/.ssh/' directory and the host's private SSH
keys) in the resulting initrd. This could lead to an information leak
when initrd files were previously created with world-readable
permissions. Note: With this update, only the SSH client
configuration, known hosts files, and the SSH key configured via the
newly introduced sshkey option in '/etc/kdump.conf' are included in
the initrd. The default is the key generated when running the 'service
kdump propagate' command, '/root/.ssh/kdump_id_rsa'. (CVE-2011-3590)

Red Hat would like to thank Kevan Carstensen for reporting these
issues.

This updated kexec-tools package also includes numerous bug fixes and
enhancements. Space precludes documenting all of these changes in this
advisory. Users are directed to the Red Hat Enterprise Linux 5.8
Technical Notes, linked to in the References, for information on the
most significant of these changes.

All users of kexec-tools are advised to upgrade to this updated
package, which resolves these security issues, fixes these bugs and
adds these enhancements."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2012-March/002650.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kexec-tools package."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kexec-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/07");
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
if (rpm_check(release:"EL5", reference:"kexec-tools-1.102pre-154.0.3.el5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kexec-tools");
}
