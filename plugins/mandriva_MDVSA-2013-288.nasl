#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2013:288. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(71508);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/12/19 11:40:37 $");

  script_cve_id("CVE-2013-4505", "CVE-2013-4558");
  script_bugtraq_id(63966, 63981);
  script_xref(name:"MDVSA", value:"2013:288");

  script_name(english:"Mandriva Linux Security Advisory : subversion (MDVSA-2013:288)");
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
"Updated subversion package fixes security vulnerabilities :

mod_dontdothat allows you to block update REPORT requests against
certain paths in the repository. It expects the paths in the REPORT
request to be absolute URLs. Serf based clients send relative URLs
instead of absolute URLs in many cases. As a result these clients are
not blocked as configured by mod_dontdothat (CVE-2013-4505).

When SVNAutoversioning is enabled via SVNAutoversioning on, commits
can be made by single HTTP requests such as MKCOL and PUT. If
Subversion is built with assertions enabled any such requests that
have non-canonical URLs, such as URLs with a trailing /, may trigger
an assert. An assert will cause the Apache process to abort
(CVE-2013-4558)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2013-0360.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache-mod_dav_svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64svn-gnome-keyring0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64svn0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64svnjavahl1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:perl-SVN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:perl-svn-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:python-svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:python-svn-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ruby-svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ruby-svn-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:subversion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:subversion-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:subversion-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:subversion-gnome-keyring-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:subversion-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:subversion-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:svn-javahl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"apache-mod_dav_svn-1.7.14-0.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64svn-gnome-keyring0-1.7.14-0.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64svn0-1.7.14-0.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64svnjavahl1-1.7.14-0.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"perl-SVN-1.7.14-0.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"perl-svn-devel-1.7.14-0.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"python-svn-1.7.14-0.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"python-svn-devel-1.7.14-0.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"ruby-svn-1.7.14-0.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"ruby-svn-devel-1.7.14-0.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"subversion-1.7.14-0.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"subversion-devel-1.7.14-0.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"subversion-doc-1.7.14-0.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"subversion-gnome-keyring-devel-1.7.14-0.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"subversion-server-1.7.14-0.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"subversion-tools-1.7.14-0.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"svn-javahl-1.7.14-0.1.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
