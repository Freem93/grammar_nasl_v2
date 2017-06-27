#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2011:106. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(54964);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/17 17:02:55 $");

  script_cve_id("CVE-2011-1752", "CVE-2011-1783", "CVE-2011-1921");
  script_bugtraq_id(48091);
  script_xref(name:"MDVSA", value:"2011:106");

  script_name(english:"Mandriva Linux Security Advisory : subversion (MDVSA-2011:106)");
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
"Multiple vulnerabilities were discovered and corrected in subversion :

The mod_dav_svn Apache HTTPD server module will dereference a NULL
pointer if asked to deliver baselined WebDAV resources which can lead
to a DoS (Denial Of Service) (CVE-2011-1752).

The mod_dav_svn Apache HTTPD server module may in certain cenarios
enter a logic loop which does not exit and which allocates emory in
each iteration, ultimately exhausting all the available emory on the
server which can lead to a DoS (Denial Of Service) (CVE-2011-1783).

The mod_dav_svn Apache HTTPD server module may leak to remote users
the file contents of files configured to be unreadable by those users
(CVE-2011-1921).

Packages for 2009.0 are provided as of the Extended Maintenance
Program. Please visit this link to learn more:
http://store.mandriva.com/product_info.php?cPath=149 products_id=490

The updated packages have been upgraded to the 1.6.17 version which is
not vulnerable to these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://svn.apache.org/repos/asf/subversion/tags/1.6.17/CHANGES"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache-mod_dav_svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache-mod_dontdothat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64svn-gnome-keyring0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64svn-kwallet0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64svn0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64svnjavahl1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libsvn-gnome-keyring0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libsvn-kwallet0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libsvn0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libsvnjavahl1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:perl-SVN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:python-svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ruby-svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:subversion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:subversion-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:subversion-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:subversion-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:subversion-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:svn-javahl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2009.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2010.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2009.0", reference:"apache-mod_dav_svn-1.6.17-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"apache-mod_dontdothat-1.6.17-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64svn0-1.6.17-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64svnjavahl1-1.6.17-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libsvn0-1.6.17-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libsvnjavahl1-1.6.17-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"perl-SVN-1.6.17-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"python-svn-1.6.17-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"ruby-svn-1.6.17-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"subversion-1.6.17-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"subversion-devel-1.6.17-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"subversion-doc-1.6.17-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"subversion-server-1.6.17-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"subversion-tools-1.6.17-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"svn-javahl-1.6.17-0.1mdv2009.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2010.1", reference:"apache-mod_dav_svn-1.6.17-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"apache-mod_dontdothat-1.6.17-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64svn-gnome-keyring0-1.6.17-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64svn-kwallet0-1.6.17-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64svn0-1.6.17-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64svnjavahl1-1.6.17-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libsvn-gnome-keyring0-1.6.17-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libsvn-kwallet0-1.6.17-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libsvn0-1.6.17-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libsvnjavahl1-1.6.17-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"perl-SVN-1.6.17-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"python-svn-1.6.17-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"ruby-svn-1.6.17-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"subversion-1.6.17-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"subversion-devel-1.6.17-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"subversion-doc-1.6.17-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"subversion-server-1.6.17-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"subversion-tools-1.6.17-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"svn-javahl-1.6.17-0.1mdv2010.2", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
