#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2012:128. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(61977);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/08/16 19:14:48 $");

  script_cve_id("CVE-2012-3410");
  script_xref(name:"MDVSA", value:"2012:128");

  script_name(english:"Mandriva Linux Security Advisory : bash (MDVSA-2012:128)");
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
"A vulnerability was found and corrected in bash :

A stack-based buffer overflow flaw was found in the way bash, the GNU
Bourne Again shell, expanded certain /dev/fd file names when checking
file names ('test' command) and evaluating /dev/fd file names in
conditinal command expressions. A remote attacker could provide a
specially crafted Bash script that, when executed, would cause the
bash executable to crash (CVE-2012-3410).

Additionally the official patches 011 to 037 for bash-4.2 has been
applied which resolves other issues found, including the CVE-2012-3410
vulnerability."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"ftp://ftp.gnu.org/gnu/bash/bash-4.2-patches/bash42-011"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"ftp://ftp.gnu.org/gnu/bash/bash-4.2-patches/bash42-012"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"ftp://ftp.gnu.org/gnu/bash/bash-4.2-patches/bash42-013"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"ftp://ftp.gnu.org/gnu/bash/bash-4.2-patches/bash42-014"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"ftp://ftp.gnu.org/gnu/bash/bash-4.2-patches/bash42-015"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"ftp://ftp.gnu.org/gnu/bash/bash-4.2-patches/bash42-016"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"ftp://ftp.gnu.org/gnu/bash/bash-4.2-patches/bash42-017"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"ftp://ftp.gnu.org/gnu/bash/bash-4.2-patches/bash42-018"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"ftp://ftp.gnu.org/gnu/bash/bash-4.2-patches/bash42-019"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"ftp://ftp.gnu.org/gnu/bash/bash-4.2-patches/bash42-020"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"ftp://ftp.gnu.org/gnu/bash/bash-4.2-patches/bash42-021"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"ftp://ftp.gnu.org/gnu/bash/bash-4.2-patches/bash42-022"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"ftp://ftp.gnu.org/gnu/bash/bash-4.2-patches/bash42-023"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"ftp://ftp.gnu.org/gnu/bash/bash-4.2-patches/bash42-024"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"ftp://ftp.gnu.org/gnu/bash/bash-4.2-patches/bash42-025"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"ftp://ftp.gnu.org/gnu/bash/bash-4.2-patches/bash42-026"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"ftp://ftp.gnu.org/gnu/bash/bash-4.2-patches/bash42-027"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"ftp://ftp.gnu.org/gnu/bash/bash-4.2-patches/bash42-028"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"ftp://ftp.gnu.org/gnu/bash/bash-4.2-patches/bash42-029"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"ftp://ftp.gnu.org/gnu/bash/bash-4.2-patches/bash42-030"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"ftp://ftp.gnu.org/gnu/bash/bash-4.2-patches/bash42-031"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"ftp://ftp.gnu.org/gnu/bash/bash-4.2-patches/bash42-032"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"ftp://ftp.gnu.org/gnu/bash/bash-4.2-patches/bash42-033"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"ftp://ftp.gnu.org/gnu/bash/bash-4.2-patches/bash42-034"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"ftp://ftp.gnu.org/gnu/bash/bash-4.2-patches/bash42-035"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"ftp://ftp.gnu.org/gnu/bash/bash-4.2-patches/bash42-036"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"ftp://ftp.gnu.org/gnu/bash/bash-4.2-patches/bash42-037"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected bash and / or bash-doc packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:bash");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:bash-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2011");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2011", reference:"bash-4.2-9.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"bash-doc-4.2-9.1-mdv2011.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
