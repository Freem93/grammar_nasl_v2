#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61339);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:57 $");

  script_cve_id("CVE-2012-2690");

  script_name(english:"Scientific Linux Security Update : libguestfs on SL6.x x86_64");
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
"libguestfs is a library for accessing and modifying guest disk images.

It was found that editing files with virt-edit left said files in a
world-readable state (and did not preserve the file owner or
Security-Enhanced Linux context). If an administrator on the host used
virt-edit to edit a file inside a guest, the file would be left with
world-readable permissions. This could lead to unprivileged guest
users accessing files they would otherwise be unable to.
(CVE-2012-2690)

These updated libguestfs packages include numerous bug fixes and
enhancements.

Users of libguestfs are advised to upgrade to these updated packages,
which fix these issues and add these enhancements."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1207&L=scientific-linux-errata&T=0&P=3608
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f7aae04a"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"libguestfs-1.16.19-1.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"libguestfs-debuginfo-1.16.19-1.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"libguestfs-devel-1.16.19-1.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"libguestfs-java-1.16.19-1.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"libguestfs-java-devel-1.16.19-1.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"libguestfs-javadoc-1.16.19-1.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"libguestfs-tools-1.16.19-1.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"libguestfs-tools-c-1.16.19-1.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"ocaml-libguestfs-1.16.19-1.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"ocaml-libguestfs-devel-1.16.19-1.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"perl-Sys-Guestfs-1.16.19-1.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"python-libguestfs-1.16.19-1.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"ruby-libguestfs-1.16.19-1.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
