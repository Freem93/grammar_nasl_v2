#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2015:170. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(82446);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/03/31 13:56:07 $");

  script_cve_id("CVE-2014-5044");
  script_xref(name:"MDVSA", value:"2015:170");

  script_name(english:"Mandriva Linux Security Advisory : gcc (MDVSA-2015:170)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Mandriva Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated gcc packages fix the following security issue :

Multiple integer overflow issues were found in libgfortran, the
run-time support library for the Fortran compiler. These could
possibly be used to crash a Fortran application or cause it to execute
arbitrary code CVE-2014-5044).

They also fix the following bugs :

The gcc rtl-optimization sched2 miscompiles syscall sequence wich can
cause random panic in glibc and kernel (gcc/PR61801)

clang++ fails to find cxxabi.h and cxxabi_tweaks.h during build
(mga#13543)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2014-0306.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gcc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gcc-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gcc-cpp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gcc-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gcc-doc-pdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gcc-gfortran");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gcc-gnat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gcc-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gcc-objc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gcc-objc++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gcc-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gcj-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64gcj-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64gcj-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64gcj14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64gcj_bc1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libasan-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libasan0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libatomic-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libatomic1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libgcc1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libgcj14-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libgcj14-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libgfortran3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libgnat1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libgomp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libgomp1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libitm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libitm1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libmudflap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libmudflap0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libobjc4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libquadmath-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libquadmath0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libstdc++-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libstdc++-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libstdc++-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libstdc++6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libtsan-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libtsan0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
  script_family(english:"Mandriva Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/Mandrake/release", "Host/Mandrake/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Mandrake/release")) audit(AUDIT_OS_NOT, "Mandriva / Mandake Linux");
if (!get_kb_item("Host/Mandrake/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^(amd64|i[3-6]86|x86_64)$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Mandriva / Mandrake Linux", cpu);


flag = 0;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"gcc-4.8.2-5.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"gcc-c++-4.8.2-5.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"gcc-cpp-4.8.2-5.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", reference:"gcc-doc-4.8.2-5.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", reference:"gcc-doc-pdf-4.8.2-5.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"gcc-gfortran-4.8.2-5.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"gcc-gnat-4.8.2-5.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"gcc-java-4.8.2-5.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"gcc-objc-4.8.2-5.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"gcc-objc++-4.8.2-5.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"gcc-plugins-4.8.2-5.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"gcj-tools-4.8.2-5.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"lib64gcj-devel-4.8.2-5.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"lib64gcj-static-devel-4.8.2-5.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"lib64gcj14-4.8.2-5.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"lib64gcj_bc1-4.8.2-5.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"libasan-devel-4.8.2-5.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"libasan0-4.8.2-5.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"libatomic-devel-4.8.2-5.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"libatomic1-4.8.2-5.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"libgcc1-4.8.2-5.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"libgcj14-base-4.8.2-5.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"libgcj14-src-4.8.2-5.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"libgfortran3-4.8.2-5.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"libgnat1-4.8.2-5.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"libgomp-devel-4.8.2-5.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"libgomp1-4.8.2-5.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"libitm-devel-4.8.2-5.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"libitm1-4.8.2-5.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"libmudflap-devel-4.8.2-5.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"libmudflap0-4.8.2-5.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"libobjc4-4.8.2-5.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"libquadmath-devel-4.8.2-5.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"libquadmath0-4.8.2-5.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"libstdc++-devel-4.8.2-5.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", reference:"libstdc++-docs-4.8.2-5.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"libstdc++-static-devel-4.8.2-5.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"libstdc++6-4.8.2-5.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"libtsan-devel-4.8.2-5.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"libtsan0-4.8.2-5.1.mbs2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
