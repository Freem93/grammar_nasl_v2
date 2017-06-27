#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2000:043. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(61836);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/05/31 23:43:24 $");

  script_xref(name:"MDKSA", value:"2000:043");

  script_name(english:"Mandrake Linux Security Advisory : Zope (MDKSA-2000:043)");
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
"The exploit that was not fixed with the previous Zope hotfix involves
the getRoles method of user objects contained in the default
UserFolder implementation returning a mutable Python type. Because the
mutable object is still associated with the persistent User object,
users with the ability to edit DTML could arrange to give themselves
extra roles for the duration of a single request by mutating the roles
list as part of the request processing. Further investigation revealed
that it was possible to access the mutable attribute directly to
perform the same exploit.

Please note that this update supercedes the previous advisory dated
August 16th (MDKSA-2000:035)."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:Zope");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:Zope-components");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:Zope-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:Zope-pcgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:Zope-services");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:Zope-zpublisher");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:Zope-zserver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:Zope-ztemplates");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:7.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2000/09/01");
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
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"Zope-2.1.6-3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"Zope-components-2.1.6-3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"Zope-core-2.1.6-3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"Zope-pcgi-2.1.6-3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"Zope-services-2.1.6-3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"Zope-zpublisher-2.1.6-3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"Zope-zserver-2.1.6-3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"Zope-ztemplates-2.1.6-3mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
