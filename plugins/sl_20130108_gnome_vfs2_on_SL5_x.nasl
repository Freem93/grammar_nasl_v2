#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(63594);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/01/17 14:07:22 $");

  script_cve_id("CVE-2009-2473");

  script_name(english:"Scientific Linux Security Update : gnome-vfs2 on SL5.x i386/x86_64");
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
"A denial of service flaw was found in the neon Extensible Markup
Language (XML) parser. Visiting a malicious DAV server with an
application using gnome-vfs2 (such as Nautilus) could possibly cause
the application to consume an excessive amount of CPU and memory.
(CVE-2009-2473)

This update also fixes the following bugs :

  - When extracted from the Uniform Resource Identifier
    (URI), gnome-vfs2 returned escaped file paths. If a
    path, as stored in the URI, contained non- ASCII
    characters or ASCII characters which are parsed as
    something other than a file path (for example, spaces),
    the escaped path was inaccurate. Consequently, files
    with the described type of URI could not be processed.
    With this update, gnome-vfs2 properly unescapes paths
    that are required for a system call. As a result, these
    paths are parsed properly.

  - In certain cases, the trash info file was populated by
    foreign entries, pointing to live data. Emptying the
    trash caused an accidental deletion of valuable data.
    With this update, a workaround has been applied in order
    to prevent the deletion. As a result, the accidental
    data loss is prevented, however further information is
    still gathered to fully fix this problem.

  - Due to a wrong test checking for a destination file
    system, the Nautilus file manager failed to delete a
    symbolic link to a folder which was residing in another
    file system. With this update, a special test has been
    added. As a result, a symbolic link pointing to another
    file system can be trashed or deleted properly.

  - Prior to this update, when directories without a read
    permission were marked for copy, the Nautilus file
    manager skipped these unreadable directories without
    notification. With this update, Nautilus displays an
    error message and properly informs the user about the
    aforementioned problem.

  - Previously, gnome-vfs2 used the stat() function calls
    for every file on the MultiVersion File System (MVFS),
    used for example by IBM Rational ClearCase. This
    behavior significantly slowed down file operations. With
    this update, the unnecessary stat() operations have been
    limited. As a result, gnome-vfs2 user interfaces, such
    as Nautilus, are more responsive."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1301&L=scientific-linux-errata&T=0&P=1703
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c2e72bf5"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/17");
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
if (rpm_check(release:"SL5", reference:"gnome-vfs2-2.16.2-10.el5")) flag++;
if (rpm_check(release:"SL5", reference:"gnome-vfs2-debuginfo-2.16.2-10.el5")) flag++;
if (rpm_check(release:"SL5", reference:"gnome-vfs2-devel-2.16.2-10.el5")) flag++;
if (rpm_check(release:"SL5", reference:"gnome-vfs2-smb-2.16.2-10.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
