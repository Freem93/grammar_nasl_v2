#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(92031);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/10/19 14:25:13 $");

  script_cve_id("CVE-2015-8869");

  script_name(english:"Scientific Linux Security Update : ocaml on SL7.x x86_64");
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
"Security Fix(es) :

  - OCaml versions 4.02.3 and earlier have a runtime bug
    that, on 64-bit platforms, causes size arguments to
    internal memmove calls to be sign- extended from 32- to
    64-bits before being passed to the memmove function.
    This leads to arguments between 2GiB and 4GiB being
    interpreted as larger than they are (specifically, a bit
    below 2^64), causing a buffer overflow. Further,
    arguments between 4GiB and 6GiB are interpreted as 4GiB
    smaller than they should be, causing a possible
    information leak. (CVE-2015-8869)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1607&L=scientific-linux-errata&F=&S=&P=75
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?573e33b4"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"brlapi-0.6.0-9.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"brlapi-devel-0.6.0-9.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"brlapi-java-0.6.0-9.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"brltty-4.5-9.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"brltty-at-spi-4.5-9.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"brltty-docs-4.5-9.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"brltty-xw-4.5-9.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"graphviz-2.30.1-19.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"graphviz-devel-2.30.1-19.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"graphviz-doc-2.30.1-19.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"graphviz-gd-2.30.1-19.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"graphviz-graphs-2.30.1-19.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"graphviz-guile-2.30.1-19.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"graphviz-java-2.30.1-19.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"graphviz-lua-2.30.1-19.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"graphviz-ocaml-2.30.1-19.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"graphviz-perl-2.30.1-19.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"graphviz-php-2.30.1-19.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"graphviz-python-2.30.1-19.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"graphviz-ruby-2.30.1-19.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"graphviz-tcl-2.30.1-19.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"hivex-1.3.10-5.7.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"hivex-devel-1.3.10-5.7.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ocaml-4.01.0-22.7.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ocaml-brlapi-0.6.0-9.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ocaml-calendar-2.03.2-5.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ocaml-calendar-devel-2.03.2-5.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ocaml-camlp4-4.01.0-22.7.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ocaml-camlp4-devel-4.01.0-22.7.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ocaml-compiler-libs-4.01.0-22.7.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ocaml-csv-1.2.3-6.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ocaml-csv-devel-1.2.3-6.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ocaml-curses-1.0.3-18.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ocaml-curses-devel-1.0.3-18.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ocaml-debuginfo-4.01.0-22.7.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ocaml-docs-4.01.0-22.7.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ocaml-emacs-4.01.0-22.7.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ocaml-extlib-1.5.3-5.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ocaml-extlib-devel-1.5.3-5.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ocaml-fileutils-0.4.4-7.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ocaml-fileutils-devel-0.4.4-7.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ocaml-findlib-1.3.3-6.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ocaml-findlib-devel-1.3.3-6.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ocaml-gettext-0.3.4-13.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ocaml-gettext-devel-0.3.4-13.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ocaml-hivex-1.3.10-5.7.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ocaml-hivex-devel-1.3.10-5.7.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ocaml-labltk-4.01.0-22.7.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ocaml-labltk-devel-4.01.0-22.7.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ocaml-libguestfs-devel-1.28.1-1.18.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ocaml-libvirt-0.6.1.2-10.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ocaml-libvirt-devel-0.6.1.2-10.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ocaml-ocamldoc-4.01.0-22.7.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ocaml-runtime-4.01.0-22.7.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ocaml-source-4.01.0-22.7.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ocaml-x11-4.01.0-22.7.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ocaml-xml-light-2.3-0.6.svn234.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ocaml-xml-light-devel-2.3-0.6.svn234.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"perl-hivex-1.3.10-5.7.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"python-brlapi-0.6.0-9.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"python-hivex-1.3.10-5.7.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ruby-hivex-1.3.10-5.7.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"tcl-brlapi-0.6.0-9.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
