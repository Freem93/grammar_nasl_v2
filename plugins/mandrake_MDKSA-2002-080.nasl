#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2002:080. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(13978);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2013/05/31 23:43:26 $");

  script_cve_id("CVE-2002-1247", "CVE-2002-1306");
  script_xref(name:"MDKSA", value:"2002:080");

  script_name(english:"Mandrake Linux Security Advisory : kdenetwork (MDKSA-2002:080)");
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
"The SuSE security team discovered two vulnerabilities in the KDE
lanbrowsing service during an audit. The LISa network daemon and
'reslisa', a restricted version of LISa are used to identify servers
on the local network by using the URL type 'lan://' and 'rlan://'
respectively. A buffer overflow was discovered in the lisa daemon that
can be exploited by an attacker on the local network to obtain root
privilege on a machine running the lisa daemon. Another buffer
overflow was found in the lan:// URL handler, which can be exploited
by a remote attacker to gain access to the victim user's account.

Only Mandrake Linux 9.0 comes with the LISa network daemon; all
previous versions do not contain the network daemon and are as such
not vulnerable."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.kde.org/info/security/advisory-20021111-2.txt"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected kdenetwork, kdenetwork-devel and / or lisa
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdenetwork");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdenetwork-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lisa");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2002/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"kdenetwork-3.0.3-15.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"kdenetwork-devel-3.0.3-15.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"lisa-3.0.3-15.1mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
