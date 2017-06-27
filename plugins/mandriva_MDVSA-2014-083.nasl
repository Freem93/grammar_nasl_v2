#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2014:083. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(73934);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/05/09 10:52:15 $");

  script_cve_id("CVE-2014-2665");
  script_bugtraq_id(66600);
  script_xref(name:"MDVSA", value:"2014:083");

  script_name(english:"Mandriva Linux Security Advisory : mediawiki (MDVSA-2014:083)");
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
"Updated mediawiki packages fix security vulnerabilities :

Login CSRF issue in MediaWiki before 1.22.5 in Special:ChangePassword,
whereby a user can be logged into an attackers account without being
aware of it, allowing the attacker to track the user's activity
(CVE-2014-2665).

XSS vulnerability in MediaWiki before 1.22.6, where if the default
sort key is set to a string containing a script, the script will be
executed when the page is viewed using the info action.

MediaWiki has been updated to version 1.22.6, fixing this and other
issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2014-0157.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2014-0197.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mediawiki");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mediawiki-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mediawiki-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mediawiki-sqlite");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK-MBS1", reference:"mediawiki-1.22.6-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"mediawiki-mysql-1.22.6-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"mediawiki-pgsql-1.22.6-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"mediawiki-sqlite-1.22.6-1.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
