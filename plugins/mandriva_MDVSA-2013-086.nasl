#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2013:086. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(66099);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/03/14 13:55:51 $");

  script_cve_id(
    "CVE-2009-5044",
    "CVE-2009-5079",
    "CVE-2009-5080",
    "CVE-2009-5081"
  );
  script_bugtraq_id(
    36381,
    53937,
    53940
  );
  script_osvdb_id(
    73111,
    74383,
    74384,
    74385,
    74386,
    74387,
    74388,
    74389,
    74390,
    74391
  );
  script_xref(name:"MDVSA", value:"2013:086");

  script_name(english:"Mandriva Linux Security Advisory : groff (MDVSA-2013:086)");
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
"Multiple vulnerabilities has been found and corrected in groff :

contrib/pdfmark/pdfroff.sh in GNU troff (aka groff) before 1.21 allows
local users to overwrite arbitrary files via a symlink attack on a
pdf#####.tmp temporary file (CVE-2009-5044).

The (1) gendef.sh, (2) doc/fixinfo.sh, and (3)
contrib/gdiffmk/tests/runtests.in scripts in GNU troff (aka groff)
1.21 and earlier allow local users to overwrite arbitrary files via a
symlink attack on a gro#####.tmp or /tmp/##### temporary file
(CVE-2009-5079).

The (1) contrib/eqn2graph/eqn2graph.sh, (2)
contrib/grap2graph/grap2graph.sh, and (3)
contrib/pic2graph/pic2graph.sh scripts in GNU troff (aka groff) 1.21
and earlier do not properly handle certain failed attempts to create
temporary directories, which might allow local users to overwrite
arbitrary files via a symlink attack on a file in a temporary
directory, a different vulnerability than CVE-2004-1296
(CVE-2009-5080).

The (1) config.guess, (2) contrib/groffer/perl/groffer.pl, and (3)
contrib/groffer/perl/roff2.pl scripts in GNU troff (aka groff) 1.21
and earlier use an insufficient number of X characters in the template
argument to the tempfile function, which makes it easier for local
users to overwrite arbitrary files via a symlink attack on a temporary
file, a different vulnerability than CVE-2004-0969 (CVE-2009-5081).

The updated packages have been patched to correct these issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:groff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:groff-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:groff-for-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:groff-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:groff-x11");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"groff-1.21-3.2.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"groff-doc-1.21-3.2.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"groff-for-man-1.21-3.2.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"groff-perl-1.21-3.2.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"groff-x11-1.21-3.2.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
