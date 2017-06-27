#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(71295);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/12/10 14:13:50 $");

  script_cve_id("CVE-2013-1813");

  script_name(english:"Scientific Linux Security Update : busybox on SL6.x i386/x86_64");
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
"It was found that the mdev BusyBox utility could create certain
directories within /dev with world-writable permissions. A local
unprivileged user could use this flaw to manipulate portions of the
/dev directory tree. (CVE-2013-1813)

This update also fixes the following bugs :

  - Previously, due to a too eager string size optimization
    on the IBM System z architecture, the 'wc' BusyBox
    command failed after processing standard input with the
    following error :

wc: : No such file or directory

This bug was fixed by disabling the string size optimization and the
'wc' command works properly on IBM System z architectures.

  - Prior to this update, the 'mknod' command was unable to
    create device nodes with a major or minor number larger
    than 255. Consequently, the kdump utility failed to
    handle such a device. The underlying source code has
    been modified, and it is now possible to use the 'mknod'
    command to create device nodes with a major or minor
    number larger than 255.

  - If a network installation from an NFS server was
    selected, the 'mount' command used the UDP protocol by
    default. If only TCP mounts were supported by the
    server, this led to a failure of the mount command. As a
    result, Anaconda could not continue with the
    installation. This bug is now fixed and NFS mount
    operations default to the TCP protocol."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1312&L=scientific-linux-errata&T=0&P=3069
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?86ca80a9"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected busybox and / or busybox-petitboot packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"busybox-1.15.1-20.el6")) flag++;
if (rpm_check(release:"SL6", reference:"busybox-petitboot-1.15.1-20.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
