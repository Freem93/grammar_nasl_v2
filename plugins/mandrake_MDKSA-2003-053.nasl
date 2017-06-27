#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2003:053. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(14037);
  script_version ("$Revision: 1.15 $");
  script_cvs_date("$Date: 2015/09/14 21:02:31 $");

  script_cve_id("CVE-2002-1391", "CVE-2002-1392");
  script_xref(name:"MDKSA", value:"2003:053");
  script_xref(name:"MDKSA", value:"2003:053-1");

  script_name(english:"Mandrake Linux Security Advisory : mgetty (MDKSA-2003:053-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Mandrake Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two vulnerabilities were discovered in mgetty versions prior to
1.1.29. An internal buffer could be overflowed if the caller name
reported by the modem, via Caller ID information, was too long. As
well, the faxspool script that comes with mgetty used a simple
permissions scheme to allow or deny fax transmission privileges.
Because the spooling directory used for outgoing faxes was
world-writable, this scheme was easily circumvented.

Update :

The installation of mgetty-sendfax on Mandrake Linux 8.2 relied on
macros that are non-existent, which would result in fresh installs of
mgetty-sendfax being unable to work. Updated packages for 8.2 correct
this."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mgetty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mgetty-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mgetty-sendfax");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mgetty-viewfax");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mgetty-voice");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:8.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"mgetty-1.1.30-1.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"mgetty-contrib-1.1.30-1.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"mgetty-sendfax-1.1.30-1.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"mgetty-viewfax-1.1.30-1.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"mgetty-voice-1.1.30-1.2mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"mgetty-1.1.30-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"mgetty-contrib-1.1.30-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"mgetty-sendfax-1.1.30-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"mgetty-viewfax-1.1.30-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"mgetty-voice-1.1.30-1.1mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
