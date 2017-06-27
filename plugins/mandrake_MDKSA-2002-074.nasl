#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2002:074. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(61919);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/05/31 23:43:26 $");

  script_cve_id("CVE-2002-1091", "CVE-2002-1126", "CVE-2002-2061", "CVE-2002-2314", "CVE-2002-2338");
  script_xref(name:"MDKSA", value:"2002:074");

  script_name(english:"Mandrake Linux Security Advisory : mozilla (MDKSA-2002:074)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Mandrake Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Numerous security fixes are available in Mozilla 1.0.1. For a detailed
list, refer to the 'Recently fixed security issues' page on the
Mozilla website (see the first reference). All users are encouraged to
upgrade to this latest stable 1.0.x release of Mozilla."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://mozilla.org/releases/mozilla1.0.1/security-fixes-1.0.1.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:galeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libjs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libnautilus0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libnautilus0-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libnspr4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libnspr4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libnss3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libnss3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-dom-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-enigmail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-enigmime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-irc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-js-debugger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-mail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-spellchecker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-xmlterm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nautilus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nautilus-mozilla");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:8.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2002/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"galeon-1.2.5-2.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"libjs-1.0.1-4.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"libnautilus0-1.0.6-15.8mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"libnautilus0-devel-1.0.6-15.8mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"libnspr4-1.0.1-4.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"libnspr4-devel-1.0.1-4.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"libnss3-1.0.1-4.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"libnss3-devel-1.0.1-4.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"mozilla-1.0.1-4.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"mozilla-devel-1.0.1-4.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"mozilla-dom-inspector-1.0.1-4.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"mozilla-enigmail-1.0.1-4.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"mozilla-enigmime-1.0.1-4.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"mozilla-irc-1.0.1-4.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"mozilla-js-debugger-1.0.1-4.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"mozilla-mail-1.0.1-4.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"mozilla-spellchecker-1.0.1-4.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"mozilla-xmlterm-1.0.1-4.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"nautilus-1.0.6-15.8mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"nautilus-mozilla-1.0.6-15.8mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
