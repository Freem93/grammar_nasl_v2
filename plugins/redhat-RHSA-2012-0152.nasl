#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0152. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58053);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2017/01/05 16:04:21 $");

  script_cve_id("CVE-2011-3588", "CVE-2011-3589", "CVE-2011-3590");
  script_bugtraq_id(50415, 50416, 50420);
  script_xref(name:"RHSA", value:"2012:0152");

  script_name(english:"RHEL 5 : kexec-tools (RHSA-2012:0152)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated kexec-tools package that resolves three security issues,
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
    value:"https://www.redhat.com/security/data/cve/CVE-2011-3588.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-3589.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-3590.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://docs.redhat.com/docs/en-US/Red_Hat_Enterprise_Linux/5/html/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2012-0152.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected kexec-tools and / or kexec-tools-debuginfo
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kexec-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kexec-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2012:0152";
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
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"kexec-tools-1.102pre-154.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"kexec-tools-1.102pre-154.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"kexec-tools-1.102pre-154.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"kexec-tools-debuginfo-1.102pre-154.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"kexec-tools-debuginfo-1.102pre-154.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"kexec-tools-debuginfo-1.102pre-154.el5")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kexec-tools / kexec-tools-debuginfo");
  }
}
