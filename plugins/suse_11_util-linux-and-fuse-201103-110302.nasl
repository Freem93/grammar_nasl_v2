#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from SuSE 11 update information. The text itself is
# copyright (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(53231);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2013/10/25 23:56:04 $");

  script_cve_id("CVE-2010-3879", "CVE-2011-0541", "CVE-2011-0543");

  script_name(english:"SuSE 11.1 Security Update : FUSE (SAT Patch Number 4095)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The following security issues were fixed :

  - FUSE allowed local users to create mtab entries with
    arbitrary pathnames, and consequently unmount any
    filesystem, via a symlink attack on the parent directory
    of the mountpoint of a FUSE filesystem. (CVE-2010-3879)

  - Avoid mounting a directory including evaluation of
    symlinks, which might have allowed local attackers to
    mount filesystems anywhere in the system.
    (CVE-2011-0541)

  - Avoid symlink attacks on the mount point written in the
    mtab file. Four bugs were fixed:. (CVE-2011-0543)

  - fixed retrying nfs mounts on rpc timeouts

  - allow seperate control of the internet protocol uses by
    rpc.mount seperately of the protocol used by nfs.

  - Fixed locking in libuuid/uuid to avoid duplicate uuids.

  - mkswap bad block check marked every block bad in O(n!)
    time on a good device New features were implemented :

  - mount now has --fake and --no-canonicalize options,
    required for the symlink security fixes. These were
    backported from mainline.

  - mount can now auto-detect and differentiate between
    squashfs3 and squashfs (v4) filesystems, allowing
    backward compatibility to the SUSE Linux Enterprise 11
    GA codebase."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=635393"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=651598"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=663385"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=666893"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=667215"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=668820"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3879.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0541.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0543.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 4095.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:fuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libblkid1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libfuse2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libuuid-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libuuid1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libuuid1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:util-linux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:util-linux-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:uuid-runtime");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2013 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)11") audit(AUDIT_OS_NOT, "SuSE 11");
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SuSE 11", cpu);

pl = get_kb_item("Host/SuSE/patchlevel");
if (isnull(pl) || int(pl) != 1) audit(AUDIT_OS_NOT, "SuSE 11.1");


flag = 0;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"fuse-2.7.2-61.23.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libblkid1-2.16-6.11.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libfuse2-2.7.2-61.23.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libuuid-devel-2.16-6.11.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libuuid1-2.16-6.11.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"util-linux-2.16-6.11.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"util-linux-lang-2.16-6.11.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"uuid-runtime-2.16-6.11.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"fuse-2.7.2-61.23.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libblkid1-2.16-6.11.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libfuse2-2.7.2-61.23.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libuuid-devel-2.16-6.11.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libuuid1-2.16-6.11.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libuuid1-32bit-2.16-6.11.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"util-linux-2.16-6.11.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"util-linux-lang-2.16-6.11.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"uuid-runtime-2.16-6.11.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"fuse-2.7.2-61.23.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"libblkid1-2.16-6.11.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"libfuse2-2.7.2-61.23.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"libuuid1-2.16-6.11.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"util-linux-2.16-6.11.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"util-linux-lang-2.16-6.11.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"uuid-runtime-2.16-6.11.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"s390x", reference:"libuuid1-32bit-2.16-6.11.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"libuuid1-32bit-2.16-6.11.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
