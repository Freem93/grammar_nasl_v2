#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1307. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63891);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2017/01/03 17:27:02 $");

  script_cve_id("CVE-2008-5188");
  script_xref(name:"RHSA", value:"2009:1307");

  script_name(english:"RHEL 5 : ecryptfs-utils (RHSA-2009:1307)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated ecryptfs-utils packages that fix a security issue, various
bugs, and add enhancements are now available for Red Hat Enterprise
Linux 5.

This update has been rated as having low security impact by the Red
Hat Security Response Team.

eCryptfs is a stacked, cryptographic file system. It is transparent to
the underlying file system and provides per-file granularity.

eCryptfs is released as a Technology Preview for Red Hat Enterprise
Linux 5.4. These updated ecryptfs-utils packages have been upgraded to
upstream version 75, which provides a number of bug fixes and
enhancements over the previous version. In addition, these packages
provide a graphical program to help configure and use eCryptfs. To
start this program, run the command :

ecryptfs-mount-helper-gui

Important: the syntax of certain eCryptfs mount options has changed.
Users who were previously using the initial Technology Preview release
of ecryptfs-utils are advised to refer to the ecryptfs(7) man page,
and to update any affected mount scripts and /etc/fstab entries for
eCryptfs file systems.

A disclosure flaw was found in the way the 'ecryptfs-setup-private'
script passed passphrases to the 'ecryptfs-wrap-passphrase' and
'ecryptfs-add-passphrase' commands as command line arguments. A local
user could obtain the passphrases of other users who were running the
script from the process listing. (CVE-2008-5188)

These updated packages provide various enhancements, including a mount
helper and supporting libraries to perform key management and mounting
functions.

Notable enhancements include :

* a new package, ecryptfs-utils-gui, has been added to this update.
This package depends on the pygtk2 and pygtk2-libglade packages and
provides the eCryptfs Mount Helper GUI program. To install the GUI,
first install ecryptfs-utils and then issue the following command :

yum install ecryptfs-utils-gui

(BZ#500997)

* the 'ecryptfs-rewrite-file' utility is now more intelligent when
dealing with non-existent files and with filtering special files such
as the '.' directory. In addition, the progress output from
'ecryptfs-rewrite-file' has been improved and is now more explicit
about the success status of each target. (BZ#500813)

* descriptions of the 'verbose' flag and the 'verbosity=[x]' option,
where [x] is either 0 or 1, were missing from a number of eCryptfs
manual pages, and have been added. Refer to the eCryptfs man pages for
important information regarding using the verbose and/or verbosity
options. (BZ#470444)

These updated packages also fix the following bugs :

* mounting a directory using the eCryptfs mount helper with an RSA key
that was too small did not allow the eCryptfs mount helper to encrypt
the entire key. When this situation occurred, the mount helper did not
display an error message alerting the user to the fact that the key
size was too small, possibly leading to corrupted files. The eCryptfs
mount helper now refuses RSA keys which are to small to encrypt the
eCryptfs key. (BZ#499175)

* when standard input was redirected from /dev/null or was
unavailable, attempting to mount a directory with the eCryptfs mount
helper caused it to become unresponsive and eventually crash, or an
'invalid value' error message, depending on if the
'--verbosity=[value]' option was provided as an argument, and, if so,
its value. With these updated packages, attempting to mount a
directory using 'mount.ecryptfs' under the same conditions results in
either the mount helper attempting to use default values (if
'verbosity=0' is supplied), or an 'invalid value' error message
(instead of the mount helper hanging) if standard input is redirected
and '--verbosity=1' is supplied, or that option is omitted entirely.
(BZ#499367)

* attempting to use the eCryptfs mount helper with an OpenSSL key when
the keyring did not contain enough space for the key resulted in an
unhelpful error message. The user is now alerted when this situation
occurs. (BZ#501460)

* the eCryptfs mount helper no longer fails upon receiving an
incorrect or empty answer to 'yes/no' questions. (BZ#466210)

Users are advised to upgrade to these updated ecryptfs-utils packages,
which resolve these issues and add these enhancements."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-5188.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2009-1307.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected ecryptfs-utils, ecryptfs-utils-devel and / or
ecryptfs-utils-gui packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(255);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ecryptfs-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ecryptfs-utils-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ecryptfs-utils-gui");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2009:1307";
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
  if (rpm_check(release:"RHEL5", reference:"ecryptfs-utils-75-5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"ecryptfs-utils-devel-75-5.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"ecryptfs-utils-gui-75-5.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"ecryptfs-utils-gui-75-5.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"ecryptfs-utils-gui-75-5.el5")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ecryptfs-utils / ecryptfs-utils-devel / ecryptfs-utils-gui");
  }
}
