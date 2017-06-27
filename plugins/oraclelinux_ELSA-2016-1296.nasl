#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2016:1296 and 
# Oracle Linux Security Advisory ELSA-2016-1296 respectively.
#

include("compat.inc");

if (description)
{
  script_id(91799);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/12/07 21:08:17 $");

  script_cve_id("CVE-2015-8869");
  script_osvdb_id(137809);
  script_xref(name:"RHSA", value:"2016:1296");

  script_name(english:"Oracle Linux 7 : ocaml (ELSA-2016-1296)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2016:1296 :

An update for ocaml is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

OCaml is a high-level, strongly-typed, functional, and object-oriented
programming language from the ML family of languages. The ocaml
packages contain two batch compilers (a fast bytecode compiler and an
optimizing native-code compiler), an interactive top level system,
parsing tools (Lex, Yacc, Camlp4), a replay debugger, a documentation
generator, and a comprehensive library.

Security Fix(es) :

* OCaml versions 4.02.3 and earlier have a runtime bug that, on 64-bit
platforms, causes size arguments to internal memmove calls to be
sign-extended from 32- to 64-bits before being passed to the memmove
function. This leads to arguments between 2GiB and 4GiB being
interpreted as larger than they are (specifically, a bit below 2^64),
causing a buffer overflow. Further, arguments between 4GiB and 6GiB
are interpreted as 4GiB smaller than they should be, causing a
possible information leak. (CVE-2015-8869)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2016-June/006140.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ocaml packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ocaml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ocaml-camlp4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ocaml-camlp4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ocaml-compiler-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ocaml-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ocaml-emacs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ocaml-labltk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ocaml-labltk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ocaml-ocamldoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ocaml-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ocaml-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ocaml-x11");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/24");
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
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"ocaml-4.01.0-22.7.el7_2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"ocaml-camlp4-4.01.0-22.7.el7_2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"ocaml-camlp4-devel-4.01.0-22.7.el7_2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"ocaml-compiler-libs-4.01.0-22.7.el7_2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"ocaml-docs-4.01.0-22.7.el7_2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"ocaml-emacs-4.01.0-22.7.el7_2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"ocaml-labltk-4.01.0-22.7.el7_2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"ocaml-labltk-devel-4.01.0-22.7.el7_2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"ocaml-ocamldoc-4.01.0-22.7.el7_2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"ocaml-runtime-4.01.0-22.7.el7_2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"ocaml-source-4.01.0-22.7.el7_2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"ocaml-x11-4.01.0-22.7.el7_2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ocaml / ocaml-camlp4 / ocaml-camlp4-devel / ocaml-compiler-libs / etc");
}
