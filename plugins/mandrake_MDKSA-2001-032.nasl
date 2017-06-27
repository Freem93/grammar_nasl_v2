#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2001:032. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(61906);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/05/31 23:43:25 $");

  script_cve_id("CVE-2001-0439", "CVE-2001-0440");
  script_xref(name:"MDKSA", value:"2001:032-1");

  script_name(english:"Mandrake Linux Security Advisory : licq (MDKSA-2001:032-1)");
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
"Versions of Licq prior to 1.0.3 have a vulnerability involving the way
Licq parses received URLs. The received URLs are passed to the web
browser without any sanity checking by using the system() function.
Because of the lack of checks on the URL, remote attackers can pipe
other commands with the sent URLs causing the client to unwillingly
execute arbitrary commands. The URL parsing code has been fixed in the
most recent 1.0.3 version.

Users of Linux-Mandrake 7.1 and Corporate Server 1.0.1 will have to
manually remove the licq-data package by using 'rpm -e licq-data'
prior to upgrading.

Update :

The Licq update for Linux-Mandrake 7.2 was built against the qt2
libraries available in MandrakeFreq. As such, the previously released
Licq packages will be made available in MandrakeFreq and users of
Linux-Mandrake 7.2 without MandrakeFreq or the 'unsupported' updates
applied should use these new packages."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:licq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:licq-autoreply");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:licq-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:licq-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:licq-forwarder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:licq-rms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:licq-update-hosts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:7.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2001/03/23");
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
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"licq-1.0.3-2.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"licq-autoreply-1.0.3-2.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"licq-console-1.0.3-2.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"licq-devel-1.0.3-2.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"licq-forwarder-1.0.3-2.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"licq-rms-1.0.3-2.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"licq-update-hosts-1.0.3-2.3mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
