#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1304. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(25529);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/12/06 20:12:50 $");

  script_cve_id("CVE-2005-4811", "CVE-2006-4623", "CVE-2006-4814", "CVE-2006-5753", "CVE-2006-5754", "CVE-2006-5757", "CVE-2006-6053", "CVE-2006-6056", "CVE-2006-6060", "CVE-2006-6106", "CVE-2006-6535", "CVE-2007-0958", "CVE-2007-1357", "CVE-2007-1592");
  script_osvdb_id(28718, 29540, 30067, 30293, 30297, 30508, 31375, 31377, 33020, 33029, 33030, 33032, 34365, 34737, 35930);
  script_xref(name:"DSA", value:"1304");

  script_name(english:"Debian DSA-1304-1 : kernel-source-2.6.8 - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"CVE-2006-6060 CVE-2006-6106 CVE-2006-6535 CVE-2007-0958 CVE-2007-1357
 CVE-2007-1592

Several local and remote vulnerabilities have been discovered in the
Linux kernel that may lead to a denial of service or the execution of
arbitrary code. 

This update also fixes a regression in the smbfs subsystem which was
introduced in DSA-1233which caused symlinks to be interpreted as
regular files.

The Common Vulnerabilities and Exposures project identifies the
following problems :

  - CVE-2005-4811
    David Gibson reported an issue in the hugepage code
    which could permit a local DoS (system crash) on
    appropriately configured systems.

  - CVE-2006-4814
    Doug Chapman discovered a potential local DoS (deadlock)
    in the mincore function caused by improper lock
    handling.

  - CVE-2006-4623
    Ang Way Chuang reported a remote DoS (crash) in the dvb
    driver which can be triggered by a ULE package with an
    SNDU length of 0.

  - CVE-2006-5753
    Eric Sandeen provided a fix for a local memory
    corruption vulnerability resulting from a
    misinterpretation of return values when operating on
    inodes which have been marked bad.

  - CVE-2006-5754
    Darrick Wong discovered a local DoS (crash)
    vulnerability resulting from the incorrect
    initialization of 'nr_pages' in aio_setup_ring().

  - CVE-2006-5757
    LMH reported a potential local DoS which could be
    exploited by a malicious user with the privileges to
    mount and read a corrupted iso9660 filesystem.

  - CVE-2006-6053
    LMH reported a potential local DoS which could be
    exploited by a malicious user with the privileges to
    mount and read a corrupted ext3 filesystem.

  - CVE-2006-6056
    LMH reported a potential local DoS which could be
    exploited by a malicious user with the privileges to
    mount and read a corrupted hfs filesystem on systems
    with SELinux hooks enabled (Debian does not enable
    SELinux by default).

  - CVE-2006-6060
    LMH reported a potential local DoS (infinite loop) which
    could be exploited by a malicious user with the
    privileges to mount and read a corrupted NTFS
    filesystem.

  - CVE-2006-6106
    Marcel Holtman discovered multiple buffer overflows in
    the Bluetooth subsystem which can be used to trigger a
    remote DoS (crash) and potentially execute arbitrary
    code.

  - CVE-2006-6535
    Kostantin Khorenko discovered an invalid error path in
    dev_queue_xmit() which could be exploited by a local
    user to cause data corruption.

  - CVE-2007-0958
    Santosh Eraniose reported a vulnerability that allows
    local users to read otherwise unreadable files by
    triggering a core dump while using PT_INTERP. This is
    related to CVE-2004-1073.

  - CVE-2007-1357
    Jean Delvare reported a vulnerability in the appletalk
    subsystem. Systems with the appletalk module loaded can
    be triggered to crash by other systems on the local
    network via a malformed frame.

  - CVE-2007-1592
    Masayuki Nakagawa discovered that flow labels were
    inadvertently being shared between listening sockets and
    child sockets. This defect can be exploited by local
    users to cause a DoS (Oops)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-6060"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-6106"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-6535"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-0958"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-1357"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-1592"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2005-4811"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-4814"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-4623"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-5753"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-5754"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-5757"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-6053"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-6056"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-6060"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-6106"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-6535"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-0958"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2004-1073"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-1357"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-1592"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2007/dsa-1304"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the kernel package immediately and reboot the machine. If you
have built a custom kernel from the kernel source package, you will
need to rebuild to take advantage of these fixes.

The following matrix explains which kernel version for which
architecture fix the problems mentioned above :

                               Debian 3.1 (sarge)           
  Source                       2.6.8-16sarge7               
  Alpha architecture           2.6.8-16sarge7               
  AMD64 architecture           2.6.8-16sarge7               
  HP Precision architecture    2.6.8-6sarge7                
  Intel IA-32 architecture     2.6.8-16sarge7               
  Intel IA-64 architecture     2.6.8-14sarge7               
  Motorola 680x0 architecture  2.6.8-4sarge7                
  PowerPC architecture         2.6.8-12sarge7               
  IBM S/390 architecture       2.6.8-5sarge7                
  Sun Sparc architecture       2.6.8-15sarge7"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:C");
  script_cwe_id(119, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-source-2.6.8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/06/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/06/18");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/11/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
  script_family(english:"Debian Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("debian_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/release")) audit(AUDIT_OS_NOT, "Debian");
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (deb_check(release:"3.1", prefix:"fai-kernels", reference:"1.9.1sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"hostap-modules-2.4.27-3-386", reference:"0.3.7-1sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"hostap-modules-2.4.27-3-586tsc", reference:"0.3.7-1sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"hostap-modules-2.4.27-3-686", reference:"0.3.7-1sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"hostap-modules-2.4.27-3-686-smp", reference:"0.3.7-1sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"hostap-modules-2.4.27-3-k6", reference:"0.3.7-1sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"hostap-modules-2.4.27-3-k7", reference:"0.3.7-1sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"hostap-modules-2.4.27-3-k7-smp", reference:"0.3.7-1sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"hostap-modules-2.6.8-4-386", reference:"0.3.7-1sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"hostap-modules-2.6.8-4-686", reference:"0.3.7-1sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"hostap-modules-2.6.8-4-686-smp", reference:"0.3.7-1sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"hostap-modules-2.6.8-4-k7", reference:"0.3.7-1sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"hostap-modules-2.6.8-4-k7-smp", reference:"0.3.7-1sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.6.8-4", reference:"2.6.8-15sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.6.8-4-power3", reference:"2.6.8-12sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.6.8-4-power3-smp", reference:"2.6.8-12sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.6.8-4-power4", reference:"2.6.8-12sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.6.8-4-power4-smp", reference:"2.6.8-12sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.6.8-4-powerpc", reference:"2.6.8-12sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.6.8-4-powerpc-smp", reference:"2.6.8-12sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-doc-2.6.8", reference:"2.6.8-16sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6-itanium", reference:"2.6.8-14sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6-itanium-smp", reference:"2.6.8-14sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6-mckinley", reference:"2.6.8-14sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6-mckinley-smp", reference:"2.6.8-14sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-13", reference:"2.6.8-16sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-13-amd64-generic", reference:"2.6.8-16sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-13-amd64-k8", reference:"2.6.8-16sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-13-amd64-k8-smp", reference:"2.6.8-16sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-13-em64t-p4", reference:"2.6.8-16sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-13-em64t-p4-smp", reference:"2.6.8-16sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-4", reference:"2.6.8-15sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-4-32", reference:"2.6.8-6sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-4-32-smp", reference:"2.6.8-6sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-4-386", reference:"2.6.8-16sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-4-64", reference:"2.6.8-6sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-4-64-smp", reference:"2.6.8-6sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-4-686", reference:"2.6.8-16sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-4-686-smp", reference:"2.6.8-16sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-4-generic", reference:"2.6.8-16sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-4-itanium", reference:"2.6.8-14sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-4-itanium-smp", reference:"2.6.8-14sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-4-k7", reference:"2.6.8-16sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-4-k7-smp", reference:"2.6.8-16sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-4-mckinley", reference:"2.6.8-14sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-4-mckinley-smp", reference:"2.6.8-14sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-4-smp", reference:"2.6.8-16sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-4-sparc32", reference:"2.6.8-15sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-4-sparc64", reference:"2.6.8-15sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-4-sparc64-smp", reference:"2.6.8-15sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6-itanium", reference:"2.6.8-14sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6-itanium-smp", reference:"2.6.8-14sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6-mckinley", reference:"2.6.8-14sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6-mckinley-smp", reference:"2.6.8-14sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-13-amd64-generic", reference:"2.6.8-16sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-13-amd64-k8", reference:"2.6.8-16sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-13-amd64-k8-smp", reference:"2.6.8-16sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-13-em64t-p4", reference:"2.6.8-16sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-13-em64t-p4-smp", reference:"2.6.8-16sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-4-32", reference:"2.6.8-6sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-4-32-smp", reference:"2.6.8-6sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-4-386", reference:"2.6.8-16sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-4-64", reference:"2.6.8-6sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-4-64-smp", reference:"2.6.8-6sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-4-686", reference:"2.6.8-16sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-4-686-smp", reference:"2.6.8-16sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-4-generic", reference:"2.6.8-16sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-4-itanium", reference:"2.6.8-14sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-4-itanium-smp", reference:"2.6.8-14sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-4-k7", reference:"2.6.8-16sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-4-k7-smp", reference:"2.6.8-16sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-4-mckinley", reference:"2.6.8-14sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-4-mckinley-smp", reference:"2.6.8-14sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-4-power3", reference:"2.6.8-12sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-4-power3-smp", reference:"2.6.8-12sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-4-power4", reference:"2.6.8-12sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-4-power4-smp", reference:"2.6.8-12sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-4-powerpc", reference:"2.6.8-12sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-4-powerpc-smp", reference:"2.6.8-12sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-4-s390", reference:"2.6.8-5sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-4-s390-tape", reference:"2.6.8-5sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-4-s390x", reference:"2.6.8-5sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-4-smp", reference:"2.6.8-16sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-4-sparc32", reference:"2.6.8-15sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-4-sparc64", reference:"2.6.8-15sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-4-sparc64-smp", reference:"2.6.8-15sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-amiga", reference:"2.6.8-4sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-atari", reference:"2.6.8-4sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-bvme6000", reference:"2.6.8-4sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-hp", reference:"2.6.8-4sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-mac", reference:"2.6.8-4sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-mvme147", reference:"2.6.8-4sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-mvme16x", reference:"2.6.8-4sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-q40", reference:"2.6.8-4sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-sun3", reference:"2.6.8-4sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-patch-2.6.8-s390", reference:"2.6.8-5sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-patch-debian-2.6.8", reference:"2.6.8-16sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-source-2.6.8", reference:"2.6.8-16sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-tree-2.6.8", reference:"2.6.8-16sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"mol-modules-2.6.8-4-powerpc", reference:"0.9.70+2.6.8+12sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"mol-modules-2.6.8-4-powerpc-smp", reference:"0.9.70+2.6.8+12sarge2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
