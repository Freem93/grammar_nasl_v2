#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1307 and 
# CentOS Errata and Security Advisory 2009:1307 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(43783);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2014/06/03 10:41:58 $");

  script_cve_id("CVE-2008-5188");
  script_xref(name:"RHSA", value:"2009:1307");

  script_name(english:"CentOS 5 : ecryptfs-utils (CESA-2009:1307)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
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
  # http://lists.centos.org/pipermail/centos-announce/2009-September/016145.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?41d58301"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-September/016146.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?36f25640"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ecryptfs-utils packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(255);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ecryptfs-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ecryptfs-utils-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ecryptfs-utils-gui");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"ecryptfs-utils-75-5.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"ecryptfs-utils-devel-75-5.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"ecryptfs-utils-gui-75-5.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
