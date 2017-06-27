#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2016:2576 and 
# Oracle Linux Security Advisory ELSA-2016-2576 respectively.
#

include("compat.inc");

if (description)
{
  script_id(94699);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/12/07 21:08:17 $");

  script_cve_id("CVE-2015-8869");
  script_osvdb_id(137809);
  script_xref(name:"RHSA", value:"2016:2576");

  script_name(english:"Oracle Linux 7 : libguestfs (ELSA-2016-2576)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2016:2576 :

An update for libguestfs and virt-p2v is now available for Red Hat
Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The libguestfs packages contain a library, which is used for accessing
and modifying virtual machine (VM) disk images.

Virt-p2v is a tool for conversion of a physical server to a virtual
guest.

The following packages have been upgraded to a newer upstream version:
libguestfs (1.32.7), virt-p2v (1.32.7). (BZ#1218766)

Security Fix(es) :

* An integer conversion flaw was found in the way OCaml's String
handled its length. Certain operations on an excessively long String
could trigger a buffer overflow or result in an information leak.
(CVE-2015-8869)

Note: The libguestfs packages in this advisory were rebuilt with a
fixed version of OCaml to address this issue.

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 7.3 Release Notes linked from the References section."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2016-November/006469.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libguestfs packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs-gfs2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs-gobject");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs-gobject-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs-gobject-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs-inspect-icons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs-java-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs-man-pages-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs-man-pages-uk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs-rescue");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs-rsync");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs-tools-c");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs-xfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:lua-guestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ocaml-libguestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ocaml-libguestfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Sys-Guestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python-libguestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ruby-libguestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:virt-dib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:virt-v2v");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libguestfs-1.32.7-3.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libguestfs-bash-completion-1.32.7-3.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libguestfs-devel-1.32.7-3.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libguestfs-gfs2-1.32.7-3.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libguestfs-gobject-1.32.7-3.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libguestfs-gobject-devel-1.32.7-3.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libguestfs-gobject-doc-1.32.7-3.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libguestfs-inspect-icons-1.32.7-3.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libguestfs-java-1.32.7-3.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libguestfs-java-devel-1.32.7-3.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libguestfs-javadoc-1.32.7-3.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libguestfs-man-pages-ja-1.32.7-3.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libguestfs-man-pages-uk-1.32.7-3.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libguestfs-rescue-1.32.7-3.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libguestfs-rsync-1.32.7-3.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libguestfs-tools-1.32.7-3.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libguestfs-tools-c-1.32.7-3.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libguestfs-xfs-1.32.7-3.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"lua-guestfs-1.32.7-3.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"ocaml-libguestfs-1.32.7-3.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"ocaml-libguestfs-devel-1.32.7-3.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"perl-Sys-Guestfs-1.32.7-3.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"python-libguestfs-1.32.7-3.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"ruby-libguestfs-1.32.7-3.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"virt-dib-1.32.7-3.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"virt-v2v-1.32.7-3.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libguestfs / libguestfs-bash-completion / libguestfs-devel / etc");
}
