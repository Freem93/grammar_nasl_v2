#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2013:235. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(69918);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2013/11/25 11:41:41 $");

  script_cve_id("CVE-2013-4301", "CVE-2013-4302", "CVE-2013-4303");
  script_bugtraq_id(62194, 62215);
  script_xref(name:"MDVSA", value:"2013:235");

  script_name(english:"Mandriva Linux Security Advisory : mediawiki (MDVSA-2013:235)");
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
"Multiple vulnerabilities has been discovered and corrected in
mediawiki :

Full path disclosure in MediaWiki before 1.20.7, when an invalid
language is specified in ResourceLoader (CVE-2013-4301).

Several API modules in MediaWiki before 1.20.7 allowed anti-CSRF
tokens to be accessed via JSONP (CVE-2013-4302).

An issue with the MediaWiki API in MediaWiki before 1.20.7 where an
invalid property name could be used for XSS with older versions of
Internet Explorer (CVE-2013-4303).

Several unspecified security issues were fixed with the 1.20.6
version. This replaces the MediaWiki 1.16.5 version, which has been
EOL upstream for quite some time now, that was shipped with MBS 1.

MediaWiki removed the Math extension for the 1.18 release, but it is
now available separately. It has been packaged in the mediawiki-math
package.

The mediawiki-graphviz and mediawiki-ldapauthentication packages have
also been updated to work with the new MediaWiki packages.

The updated packages provides a solution to these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2013-0226.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2013-0276.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mediawiki");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mediawiki-graphviz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mediawiki-ldapauthentication");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mediawiki-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mediawiki-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mediawiki-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mediawiki-sqlite");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/17");
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
if (rpm_check(release:"MDK-MBS1", reference:"mediawiki-1.20.7-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"mediawiki-graphviz-0.9-1.89857.4.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"mediawiki-ldapauthentication-2.0c-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"mediawiki-math-1.0-1.110614.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"mediawiki-mysql-1.20.7-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"mediawiki-pgsql-1.20.7-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"mediawiki-sqlite-1.20.7-1.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
