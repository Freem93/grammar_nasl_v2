#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2014:182. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(77839);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/09/25 12:44:19 $");

  script_cve_id("CVE-2014-0103", "CVE-2014-5447", "CVE-2014-5448", "CVE-2014-5449", "CVE-2014-5450");
  script_bugtraq_id(68247, 69362, 69365, 69369, 69370);
  script_xref(name:"MDVSA", value:"2014:182");

  script_name(english:"Mandriva Linux Security Advisory : zarafa (MDVSA-2014:182)");
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
"Updated zarafa packages fix security vulnerabilities :

Robert Scheck reported that Zarafa's WebAccess stored session
information, including login credentials, on-disk in PHP session
files. This session file would contain a user's username and password
to the Zarafa IMAP server (CVE-2014-0103).

Robert Scheck discovered that the Zarafa Collaboration Platform has
multiple incorrect default permissions (CVE-2014-5447, CVE-2014-5448,
CVE-2014-5449, CVE-2014-5450)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2014-0380.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64zarafa-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64zarafa0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-mapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:python-MAPI");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:zarafa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:zarafa-archiver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:zarafa-caldav");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:zarafa-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:zarafa-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:zarafa-dagent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:zarafa-gateway");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:zarafa-ical");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:zarafa-indexer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:zarafa-monitor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:zarafa-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:zarafa-spooler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:zarafa-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:zarafa-webaccess");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/25");
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
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64zarafa-devel-7.1.8-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64zarafa0-7.1.8-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"php-mapi-7.1.8-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"python-MAPI-7.1.8-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"zarafa-7.1.8-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"zarafa-archiver-7.1.8-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"zarafa-caldav-7.1.8-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"zarafa-client-7.1.8-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"zarafa-common-7.1.8-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"zarafa-dagent-7.1.8-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"zarafa-gateway-7.1.8-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"zarafa-ical-7.1.8-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"zarafa-indexer-7.1.8-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"zarafa-monitor-7.1.8-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"zarafa-server-7.1.8-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"zarafa-spooler-7.1.8-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"zarafa-utils-7.1.8-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"zarafa-webaccess-7.1.8-1.1.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
