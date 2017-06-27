#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2013:236. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(69939);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/17 17:13:09 $");

  script_cve_id("CVE-2013-4277");
  script_bugtraq_id(62266);
  script_xref(name:"MDVSA", value:"2013:236");

  script_name(english:"Mandriva Linux Security Advisory : subversion (MDVSA-2013:236)");
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
"Updated subversion package fixes security vulnerability :

svnserve takes a --pid-file option which creates a file containing the
process id it is running as. It does not take steps to ensure that the
file it has been directed at is not a symlink. If the pid file is in a
directory writeable by unprivileged users, the destination could be
replaced by a symlink allowing for privilege escalation. svnserve does
not create a pid file by default (CVE-2013-4277)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2013-0275.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/18");
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
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"apache-mod_dav_svn-1.7.13-0.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64svn-gnome-keyring0-1.7.13-0.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64svn0-1.7.13-0.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64svnjavahl1-1.7.13-0.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"perl-SVN-1.7.13-0.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"perl-svn-devel-1.7.13-0.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"python-svn-1.7.13-0.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"python-svn-devel-1.7.13-0.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"ruby-svn-1.7.13-0.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"ruby-svn-devel-1.7.13-0.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"subversion-1.7.13-0.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"subversion-devel-1.7.13-0.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"subversion-doc-1.7.13-0.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"subversion-gnome-keyring-devel-1.7.13-0.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"subversion-server-1.7.13-0.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"subversion-tools-1.7.13-0.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"svn-javahl-1.7.13-0.1.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
