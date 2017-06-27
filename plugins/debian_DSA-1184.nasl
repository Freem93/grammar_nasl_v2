#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1184. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(22726);
  script_version("$Revision: 1.25 $");
  script_cvs_date("$Date: 2016/12/06 20:12:50 $");

  script_cve_id("CVE-2004-2660", "CVE-2005-4798", "CVE-2006-1052", "CVE-2006-1343", "CVE-2006-1528", "CVE-2006-1855", "CVE-2006-1856", "CVE-2006-2444", "CVE-2006-2446", "CVE-2006-2935", "CVE-2006-2936", "CVE-2006-3468", "CVE-2006-3745", "CVE-2006-4093", "CVE-2006-4145", "CVE-2006-4535");
  script_bugtraq_id(17203, 17830, 18081, 18099, 18101, 18105, 18847, 19033, 19396, 19562, 19615, 19666, 20087);
  script_osvdb_id(24071, 25232, 25744, 25745, 25747, 25750, 26552, 27119, 27540, 27781, 27812, 27973, 28034, 28119, 28120, 28315, 28551, 28937, 29841);
  script_xref(name:"CERT", value:"681569");
  script_xref(name:"DSA", value:"1184");

  script_name(english:"Debian DSA-1184-2 : kernel-source-2.6.8 - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This advisory covers the S/390 components of the recent security
update for the Linux 2.6.8 kernel that were missing due to technical
problems. For reference, please see the text of the original advisory.

  Several security related problems have been discovered in the Linux
  kernel which may lead to a denial of service or even the execution
  of arbitrary code. The Common Vulnerabilities and Exposures project
  identifies the following problems :

    - CVE-2004-2660
      Toshihiro Iwamoto discovered a memory leak in the
      handling of direct I/O writes that allows local users
      to cause a denial of service.

    - CVE-2005-4798
      A buffer overflow in NFS readlink handling allows a
      malicious remote server to cause a denial of service.

    - CVE-2006-1052
      Stephen Smalley discovered a bug in the SELinux ptrace
      handling that allows local users with ptrace
      permissions to change the tracer SID to the SID of
      another process.

    - CVE-2006-1343
      Pavel Kankovsky discovered an information leak in the
      getsockopt system call which can be exploited by a
      local program to leak potentially sensitive memory to
      userspace.

    - CVE-2006-1528
      Douglas Gilbert reported a bug in the sg driver that
      allows local users to cause a denial of service by
      performing direct I/O transfers from the sg driver to
      memory mapped I/O space.

    - CVE-2006-1855
      Mattia Belletti noticed that certain debugging code
      left in the process management code could be exploited
      by a local attacker to cause a denial of service.

    - CVE-2006-1856
      Kostik Belousov discovered a missing LSM
      file_permission check in the readv and writev
      functions which might allow attackers to bypass
      intended access restrictions.

    - CVE-2006-2444
      Patrick McHardy discovered a bug in the SNMP NAT
      helper that allows remote attackers to cause a denial
      of service.

    - CVE-2006-2446
      A race condition in the socket buffer handling allows
      remote attackers to cause a denial of service.

    - CVE-2006-2935
      Diego Calleja Garcia discovered a buffer overflow in
      the DVD handling code that could be exploited by a
      specially crafted DVD USB storage device to execute
      arbitrary code.

    - CVE-2006-2936
      A bug in the serial USB driver has been discovered
      that could be exploited by a custom made USB serial
      adapter to consume arbitrary amounts of memory.

    - CVE-2006-3468
      James McKenzie discovered a denial of service
      vulnerability in the NFS driver. When exporting an
      ext3 file system over NFS, a remote attacker could
      exploit this to trigger a file system panic by sending
      a specially crafted UDP packet.

    - CVE-2006-3745
      Wei Wang discovered a bug in the SCTP implementation
      that allows local users to cause a denial of service
      and possibly gain root privileges.

    - CVE-2006-4093
      Olof Johansson discovered that the kernel does not
      disable the HID0 bit on PowerPC 970 processors which
      could be exploited by a local attacker to cause a
      denial of service.

    - CVE-2006-4145
      A bug in the Universal Disk Format (UDF) filesystem
      driver could be exploited by a local user to cause a
      denial of service.

    - CVE-2006-4535
      David Miller reported a problem with the fix for
      CVE-2006-3745 that allows local users to crash the
      system via an SCTP socket with a certain SO_LINGER
      value.

The following matrix explains which kernel version for which
architecture fixes the problem mentioned above :

                              stable (sarge)               
  Source                       2.6.8-16sarge5               
  Alpha architecture           2.6.8-16sarge5               
  AMD64 architecture           2.6.8-16sarge5               
  HP Precision architecture    2.6.8-6sarge5                
  Intel IA-32 architecture     2.6.8-16sarge5               
  Intel IA-64 architecture     2.6.8-14sarge5               
  Motorola 680x0 architecture  2.6.8-4sarge5                
  PowerPC architecture         2.6.8-12sarge5               
  IBM S/390                    2.6.8-5sarge5                
  Sun Sparc architecture       2.6.8-15sarge5               
  FAI                          1.9.1sarge4"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2004-2660"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2005-4798"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-1052"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-1343"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-1528"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-1855"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-1856"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-2444"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-2446"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-2935"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-2936"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-3468"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-3745"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-4093"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-4145"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-4535"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-3745"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2006/dsa-1184"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the kernel package and reboot the machine. If you have built a
custom kernel from the kernel source package, you will need to rebuild
to take advantage of these fixes."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-source-2.6.8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/06/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"fai-kernels", reference:"1.9.1sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.6.8-2", reference:"2.6.8-15sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.6.8-3", reference:"2.6.8-15sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.6.8-3-power3", reference:"2.6.8-12sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.6.8-3-power3-smp", reference:"2.6.8-12sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.6.8-3-power4", reference:"2.6.8-12sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.6.8-3-power4-smp", reference:"2.6.8-12sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.6.8-3-powerpc", reference:"2.6.8-12sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.6.8-3-powerpc-smp", reference:"2.6.8-12sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.6.8-power3", reference:"2.6.8-12sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.6.8-power3-smp", reference:"2.6.8-12sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.6.8-power4", reference:"2.6.8-12sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.6.8-power4-smp", reference:"2.6.8-12sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.6.8-powerpc", reference:"2.6.8-12sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.6.8-powerpc-smp", reference:"2.6.8-12sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-doc-2.6.8", reference:"2.6.8-16sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6-itanium", reference:"2.6.8-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6-itanium-smp", reference:"2.6.8-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6-mckinley", reference:"2.6.8-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6-mckinley-smp", reference:"2.6.8-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8", reference:"2.6.8-12sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-11", reference:"2.6.8-16sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-11-amd64-generic", reference:"2.6.8-16sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-11-amd64-k8", reference:"2.6.8-16sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-11-amd64-k8-smp", reference:"2.6.8-16sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-11-em64t-p4", reference:"2.6.8-16sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-11-em64t-p4-smp", reference:"2.6.8-16sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-12", reference:"2.6.8-16sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-12-amd64-generic", reference:"2.6.8-16sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-12-amd64-k8", reference:"2.6.8-16sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-12-amd64-k8-smp", reference:"2.6.8-16sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-12-em64t-p4", reference:"2.6.8-16sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-12-em64t-p4-smp", reference:"2.6.8-16sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-2", reference:"2.6.8-15sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-2-32", reference:"2.6.8-6sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-2-32-smp", reference:"2.6.8-6sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-2-386", reference:"2.6.8-16sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-2-64", reference:"2.6.8-6sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-2-64-smp", reference:"2.6.8-6sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-2-686", reference:"2.6.8-16sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-2-686-smp", reference:"2.6.8-16sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-2-generic", reference:"2.6.8-16sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-2-itanium", reference:"2.6.8-14sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-2-itanium-smp", reference:"2.6.8-14sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-2-k7", reference:"2.6.8-16sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-2-k7-smp", reference:"2.6.8-16sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-2-mckinley", reference:"2.6.8-14sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-2-mckinley-smp", reference:"2.6.8-14sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-2-smp", reference:"2.6.8-16sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-2-sparc32", reference:"2.6.8-15sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-2-sparc64", reference:"2.6.8-15sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-2-sparc64-smp", reference:"2.6.8-15sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3", reference:"2.6.8-15sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-32", reference:"2.6.8-6sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-32-smp", reference:"2.6.8-6sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-386", reference:"2.6.8-16sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-64", reference:"2.6.8-6sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-64-smp", reference:"2.6.8-6sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-686", reference:"2.6.8-16sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-686-smp", reference:"2.6.8-16sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-generic", reference:"2.6.8-16sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-itanium", reference:"2.6.8-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-itanium-smp", reference:"2.6.8-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-k7", reference:"2.6.8-16sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-k7-smp", reference:"2.6.8-16sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-mckinley", reference:"2.6.8-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-mckinley-smp", reference:"2.6.8-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-smp", reference:"2.6.8-16sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-sparc32", reference:"2.6.8-15sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-sparc64", reference:"2.6.8-15sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-sparc64-smp", reference:"2.6.8-15sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6-itanium", reference:"2.6.8-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6-itanium-smp", reference:"2.6.8-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6-mckinley", reference:"2.6.8-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6-mckinley-smp", reference:"2.6.8-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-11-amd64-generic", reference:"2.6.8-16sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-11-amd64-k8", reference:"2.6.8-16sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-11-amd64-k8-smp", reference:"2.6.8-16sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-11-em64t-p4", reference:"2.6.8-16sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-11-em64t-p4-smp", reference:"2.6.8-16sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-12-amd64-generic", reference:"2.6.8-16sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-12-amd64-k8", reference:"2.6.8-16sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-12-amd64-k8-smp", reference:"2.6.8-16sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-12-em64t-p4", reference:"2.6.8-16sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-12-em64t-p4-smp", reference:"2.6.8-16sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-2-32", reference:"2.6.8-6sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-2-32-smp", reference:"2.6.8-6sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-2-386", reference:"2.6.8-16sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-2-64", reference:"2.6.8-6sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-2-64-smp", reference:"2.6.8-6sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-2-686", reference:"2.6.8-16sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-2-686-smp", reference:"2.6.8-16sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-2-generic", reference:"2.6.8-16sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-2-itanium", reference:"2.6.8-14sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-2-itanium-smp", reference:"2.6.8-14sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-2-k7", reference:"2.6.8-16sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-2-k7-smp", reference:"2.6.8-16sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-2-mckinley", reference:"2.6.8-14sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-2-mckinley-smp", reference:"2.6.8-14sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-2-smp", reference:"2.6.8-16sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-2-sparc32", reference:"2.6.8-15sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-2-sparc64", reference:"2.6.8-15sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-2-sparc64-smp", reference:"2.6.8-15sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-32", reference:"2.6.8-6sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-32-smp", reference:"2.6.8-6sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-386", reference:"2.6.8-16sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-64", reference:"2.6.8-6sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-64-smp", reference:"2.6.8-6sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-686", reference:"2.6.8-16sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-686-smp", reference:"2.6.8-16sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-generic", reference:"2.6.8-16sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-itanium", reference:"2.6.8-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-itanium-smp", reference:"2.6.8-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-k7", reference:"2.6.8-16sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-k7-smp", reference:"2.6.8-16sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-mckinley", reference:"2.6.8-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-mckinley-smp", reference:"2.6.8-14sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-power3", reference:"2.6.8-12sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-power3-smp", reference:"2.6.8-12sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-power4", reference:"2.6.8-12sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-power4-smp", reference:"2.6.8-12sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-powerpc", reference:"2.6.8-12sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-powerpc-smp", reference:"2.6.8-12sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-s390", reference:"2.6.8-5sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-s390-tape", reference:"2.6.8-5sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-s390x", reference:"2.6.8-5sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-smp", reference:"2.6.8-16sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-sparc32", reference:"2.6.8-15sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-sparc64", reference:"2.6.8-15sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-sparc64-smp", reference:"2.6.8-15sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-amiga", reference:"2.6.8-4sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-atari", reference:"2.6.8-4sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-bvme6000", reference:"2.6.8-4sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-hp", reference:"2.6.8-4sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-mac", reference:"2.6.8-4sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-mvme147", reference:"2.6.8-4sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-mvme16x", reference:"2.6.8-4sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-power3", reference:"2.6.8-12sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-power3-smp", reference:"2.6.8-12sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-power4", reference:"2.6.8-12sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-power4-smp", reference:"2.6.8-12sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-powerpc", reference:"2.6.8-12sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-powerpc-smp", reference:"2.6.8-12sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-q40", reference:"2.6.8-4sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-sun3", reference:"2.6.8-4sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-patch-2.6.8-s390", reference:"2.6.8-5sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-patch-debian-2.6.8", reference:"2.6.8-16sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-source-2.6.8", reference:"2.6.8-16sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-tree-2.6.8", reference:"2.6.8-16sarge5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
