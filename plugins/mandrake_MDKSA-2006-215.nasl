#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2006:215. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(24600);
  script_version ("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/03/19 14:49:26 $");

  script_cve_id("CVE-2006-5461");
  script_bugtraq_id(21016);
  script_xref(name:"MDKSA", value:"2006:215");

  script_name(english:"Mandrake Linux Security Advisory : avahi (MDKSA-2006:215)");
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
"Steve Grubb discovered that netlink messages were not being checked
for their sender identity. This could lead to local users manipulating
the Avahi service.

Packages have been patched to correct this issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:avahi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:avahi-dnsconfd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:avahi-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:avahi-sharp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:avahi-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64avahi-client3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64avahi-client3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64avahi-common3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64avahi-common3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64avahi-compat-howl0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64avahi-compat-howl0-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64avahi-compat-libdns_sd1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64avahi-compat-libdns_sd1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64avahi-core4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64avahi-core4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64avahi-glib1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64avahi-glib1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64avahi-qt3_1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64avahi-qt3_1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64avahi-qt4_1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64avahi-qt4_1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libavahi-client3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libavahi-client3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libavahi-common3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libavahi-common3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libavahi-compat-howl0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libavahi-compat-howl0-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libavahi-compat-libdns_sd1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libavahi-compat-libdns_sd1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libavahi-core4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libavahi-core4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libavahi-glib1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libavahi-glib1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libavahi-qt3_1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libavahi-qt3_1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libavahi-qt4_1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libavahi-qt4_1-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2007");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/11/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/02/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2007.0", reference:"avahi-0.6.13-4.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"avahi-dnsconfd-0.6.13-4.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"avahi-python-0.6.13-4.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"avahi-sharp-0.6.13-4.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"avahi-x11-0.6.13-4.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64avahi-client3-0.6.13-4.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64avahi-client3-devel-0.6.13-4.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64avahi-common3-0.6.13-4.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64avahi-common3-devel-0.6.13-4.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64avahi-compat-howl0-0.6.13-4.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64avahi-compat-howl0-devel-0.6.13-4.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64avahi-compat-libdns_sd1-0.6.13-4.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64avahi-compat-libdns_sd1-devel-0.6.13-4.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64avahi-core4-0.6.13-4.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64avahi-core4-devel-0.6.13-4.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64avahi-glib1-0.6.13-4.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64avahi-glib1-devel-0.6.13-4.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64avahi-qt3_1-0.6.13-4.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64avahi-qt3_1-devel-0.6.13-4.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64avahi-qt4_1-0.6.13-4.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64avahi-qt4_1-devel-0.6.13-4.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libavahi-client3-0.6.13-4.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libavahi-client3-devel-0.6.13-4.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libavahi-common3-0.6.13-4.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libavahi-common3-devel-0.6.13-4.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libavahi-compat-howl0-0.6.13-4.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libavahi-compat-howl0-devel-0.6.13-4.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libavahi-compat-libdns_sd1-0.6.13-4.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libavahi-compat-libdns_sd1-devel-0.6.13-4.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libavahi-core4-0.6.13-4.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libavahi-core4-devel-0.6.13-4.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libavahi-glib1-0.6.13-4.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libavahi-glib1-devel-0.6.13-4.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libavahi-qt3_1-0.6.13-4.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libavahi-qt3_1-devel-0.6.13-4.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libavahi-qt4_1-0.6.13-4.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libavahi-qt4_1-devel-0.6.13-4.1mdv2007.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
