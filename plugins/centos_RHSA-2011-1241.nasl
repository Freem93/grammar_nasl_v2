#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1241 and 
# CentOS Errata and Security Advisory 2011:1241 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(56273);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/05/19 23:52:00 $");

  script_cve_id("CVE-2011-1831", "CVE-2011-1832", "CVE-2011-1833", "CVE-2011-1834", "CVE-2011-1835", "CVE-2011-1837", "CVE-2011-3145");
  script_bugtraq_id(49108, 49287);
  script_osvdb_id(74879, 74880);
  script_xref(name:"RHSA", value:"2011:1241");

  script_name(english:"CentOS 5 : ecryptfs-utils (CESA-2011:1241)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
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
  # http://lists.centos.org/pipermail/centos-announce/2011-September/017811.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?39512541"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-September/017812.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b9b836d8"
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2011-September/000040.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7672a206"
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2011-September/000041.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5a8f1cbe"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ecryptfs-utils packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ecryptfs-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ecryptfs-utils-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ecryptfs-utils-gui");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/CentOS/release")) audit(AUDIT_OS_NOT, "CentOS");
if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"ecryptfs-utils-75-5.el5_7.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"ecryptfs-utils-devel-75-5.el5_7.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"ecryptfs-utils-gui-75-5.el5_7.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
