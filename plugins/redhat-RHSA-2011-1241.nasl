#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1241. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56028);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2017/01/04 16:02:23 $");

  script_cve_id("CVE-2011-1831", "CVE-2011-1832", "CVE-2011-1833", "CVE-2011-1834", "CVE-2011-1835", "CVE-2011-1837", "CVE-2011-3145");
  script_bugtraq_id(49108, 49287);
  script_osvdb_id(74879, 74880);
  script_xref(name:"RHSA", value:"2011:1241");

  script_name(english:"RHEL 5 / 6 : ecryptfs-utils (RHSA-2011:1241)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated ecryptfs-utils packages that fix several security issues are
now available for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

eCryptfs is a stacked, cryptographic file system. It is transparent to
the underlying file system and provides per-file granularity. eCryptfs
is released as a Technology Preview for Red Hat Enterprise Linux 5 and
6.

The setuid mount.ecryptfs_private utility allows users to mount an
eCryptfs file system. This utility can only be run by users in the
'ecryptfs' group.

A race condition flaw was found in the way mount.ecryptfs_private
checked the permissions of a requested mount point when mounting an
encrypted file system. A local attacker could possibly use this flaw
to escalate their privileges by mounting over an arbitrary directory.
(CVE-2011-1831)

A race condition flaw in umount.ecryptfs_private could allow a local
attacker to unmount an arbitrary file system. (CVE-2011-1832)

It was found that mount.ecryptfs_private did not handle certain errors
correctly when updating the mtab (mounted file systems table) file,
allowing a local attacker to corrupt the mtab file and possibly
unmount an arbitrary file system. (CVE-2011-1834)

An insecure temporary file use flaw was found in the
ecryptfs-setup-private script. A local attacker could use this script
to insert their own key that will subsequently be used by a new user,
possibly giving the attacker access to the user's encrypted data if
existing file permissions allow access. (CVE-2011-1835)

A race condition flaw in mount.ecryptfs_private could allow a local
attacker to overwrite arbitrary files. (CVE-2011-1837)

A race condition flaw in the way temporary files were accessed in
mount.ecryptfs_private could allow a malicious, local user to make
arbitrary modifications to the mtab file. (CVE-2011-3145)

A race condition flaw was found in the way mount.ecryptfs_private
checked the permissions of the directory to mount. A local attacker
could use this flaw to mount (and then access) a directory they would
otherwise not have access to. Note: The fix for this issue is
incomplete until a kernel-space change is made. Future Red Hat
Enterprise Linux 5 and 6 kernel updates will correct this issue.
(CVE-2011-1833)

Red Hat would like to thank the Ubuntu Security Team for reporting
these issues. The Ubuntu Security Team acknowledges Vasiliy Kulikov of
Openwall and Dan Rosenberg as the original reporters of CVE-2011-1831,
CVE-2011-1832, and CVE-2011-1833; Dan Rosenberg and Marc Deslauriers
as the original reporters of CVE-2011-1834; Marc Deslauriers as the
original reporter of CVE-2011-1835; and Vasiliy Kulikov of Openwall as
the original reporter of CVE-2011-1837.

Users of ecryptfs-utils are advised to upgrade to these updated
packages, which contain backported patches to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1831.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1832.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1834.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1835.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1837.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-3145.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/support/offerings/techpreview/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2011-1241.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ecryptfs-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ecryptfs-utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ecryptfs-utils-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ecryptfs-utils-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ecryptfs-utils-python");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/01");
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
if (! ereg(pattern:"^(5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x / 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2011:1241";
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
  if (rpm_check(release:"RHEL5", reference:"ecryptfs-utils-75-5.el5_7.2")) flag++;

  if (rpm_check(release:"RHEL5", reference:"ecryptfs-utils-devel-75-5.el5_7.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"ecryptfs-utils-gui-75-5.el5_7.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"ecryptfs-utils-gui-75-5.el5_7.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"ecryptfs-utils-gui-75-5.el5_7.2")) flag++;


  if (rpm_check(release:"RHEL6", reference:"ecryptfs-utils-82-6.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", reference:"ecryptfs-utils-debuginfo-82-6.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", reference:"ecryptfs-utils-devel-82-6.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"ecryptfs-utils-python-82-6.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"ecryptfs-utils-python-82-6.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ecryptfs-utils-python-82-6.el6_1.3")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ecryptfs-utils / ecryptfs-utils-debuginfo / ecryptfs-utils-devel / etc");
  }
}
