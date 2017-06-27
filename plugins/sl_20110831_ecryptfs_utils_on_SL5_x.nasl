#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61124);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/02/19 11:43:47 $");

  script_cve_id("CVE-2011-1831", "CVE-2011-3145");

  script_name(english:"Scientific Linux Security Update : ecryptfs-utils on SL5.x, SL6.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"eCryptfs is a stacked, cryptographic file system. It is transparent to
the underlying file system and provides per-file granularity.

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
incomplete until a kernel-space change is made. Future Scientific
Linux 5 and 6 kernel updates will correct this issue. (CVE-2011-1833)

Users of ecryptfs-utils are advised to upgrade to these updated
packages, which contain backported patches to correct these issues."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1109&L=scientific-linux-errata&T=0&P=615
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bc5c4829"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL5", reference:"ecryptfs-utils-75-5.el5_7.2")) flag++;
if (rpm_check(release:"SL5", reference:"ecryptfs-utils-debuginfo-75-5.el5_7.2")) flag++;
if (rpm_check(release:"SL5", reference:"ecryptfs-utils-devel-75-5.el5_7.2")) flag++;
if (rpm_check(release:"SL5", reference:"ecryptfs-utils-gui-75-5.el5_7.2")) flag++;

if (rpm_check(release:"SL6", reference:"ecryptfs-utils-82-6.el6_1.3")) flag++;
if (rpm_check(release:"SL6", reference:"ecryptfs-utils-debuginfo-82-6.el6_1.3")) flag++;
if (rpm_check(release:"SL6", reference:"ecryptfs-utils-devel-82-6.el6_1.3")) flag++;
if (rpm_check(release:"SL6", reference:"ecryptfs-utils-python-82-6.el6_1.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
