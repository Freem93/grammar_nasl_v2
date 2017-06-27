#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60933);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/08/16 19:42:09 $");

  script_cve_id("CVE-2010-0831", "CVE-2010-2322");

  script_name(english:"Scientific Linux Security Update : gcc on SL5.x i386/x86_64");
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
"Two directory traversal flaws were found in the way fastjar extracted
JAR archive files. If a local, unsuspecting user extracted a specially
crafted JAR file, it could cause fastjar to overwrite arbitrary files
writable by the user running fastjar. (CVE-2010-0831, CVE-2010-2322)

This update also fixes the following bugs :

  - The option -print-multi-os-directory in the gcc --help
    output is not in the gcc(1) man page. This update
    applies an upstream patch to amend this. (BZ#529659)

  - An internal assertion in the compiler tried to check
    that a C++ static data member is external which resulted
    in errors. This was because when the compiler optimizes
    C++ anonymous namespaces the declarations were no longer
    marked external as everything on anonymous namespaces is
    local to the current translation. This update corrects
    the assertion to resolve this issue. (BZ#503565,
    BZ#508735, BZ#582682)

  - Attempting to compile certain .cpp files could have
    resulted in an internal compiler error. This update
    resolves this issue. (BZ#527510)

  - PrintServiceLookup.lookupPrintServices with an
    appropriate DocFlavor failed to return a list of
    printers under gcj. This update includes a backported
    patch to correct this bug in the printer lookup service.
    (BZ#578382)

  - GCC would not build against xulrunner-devel-1.9.2. This
    update removes gcjwebplugin from the GCC RPM.
    (BZ#596097)

  - When a SystemTap generated kernel module was compiled,
    gcc reported an internal compiler error and gets a
    segmentation fault. This update applies a patch that,
    instead of crashing, assumes it can point to anything.
    (BZ#605803)

  - There was a performance issue with libstdc++ regarding
    all objects derived from or using std::streambuf because
    of lock contention between threads. This patch ensures
    reload uses the same value from _S_global for the
    comparison, _M_add_reference () and _M_impl member of
    the class. (BZ#635708)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1102&L=scientific-linux-errata&T=0&P=1613
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?277f87dc"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=503565"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=508735"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=527510"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=529659"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=578382"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=582682"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=596097"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=605803"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=635708"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"cpp-4.1.2-50.el5")) flag++;
if (rpm_check(release:"SL5", reference:"gcc-4.1.2-50.el5")) flag++;
if (rpm_check(release:"SL5", reference:"gcc-c++-4.1.2-50.el5")) flag++;
if (rpm_check(release:"SL5", reference:"gcc-gfortran-4.1.2-50.el5")) flag++;
if (rpm_check(release:"SL5", reference:"gcc-gnat-4.1.2-50.el5")) flag++;
if (rpm_check(release:"SL5", reference:"gcc-java-4.1.2-50.el5")) flag++;
if (rpm_check(release:"SL5", reference:"gcc-objc-4.1.2-50.el5")) flag++;
if (rpm_check(release:"SL5", reference:"gcc-objc++-4.1.2-50.el5")) flag++;
if (rpm_check(release:"SL5", reference:"libgcc-4.1.2-50.el5")) flag++;
if (rpm_check(release:"SL5", reference:"libgcj-4.1.2-50.el5")) flag++;
if (rpm_check(release:"SL5", reference:"libgcj-devel-4.1.2-50.el5")) flag++;
if (rpm_check(release:"SL5", reference:"libgcj-src-4.1.2-50.el5")) flag++;
if (rpm_check(release:"SL5", reference:"libgfortran-4.1.2-50.el5")) flag++;
if (rpm_check(release:"SL5", reference:"libgnat-4.1.2-50.el5")) flag++;
if (rpm_check(release:"SL5", reference:"libmudflap-4.1.2-50.el5")) flag++;
if (rpm_check(release:"SL5", reference:"libmudflap-devel-4.1.2-50.el5")) flag++;
if (rpm_check(release:"SL5", reference:"libobjc-4.1.2-50.el5")) flag++;
if (rpm_check(release:"SL5", reference:"libstdc++-4.1.2-50.el5")) flag++;
if (rpm_check(release:"SL5", reference:"libstdc++-devel-4.1.2-50.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
