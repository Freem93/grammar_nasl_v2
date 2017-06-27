#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2010:204. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(49989);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2013/06/01 00:15:50 $");

  script_cve_id("CVE-2010-2244");
  script_bugtraq_id(41075);
  script_xref(name:"MDVSA", value:"2010:204");

  script_name(english:"Mandriva Linux Security Advisory : avahi (MDVSA-2010:204)");
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
"A vulnerability was discovered and corrected in avahi :

The AvahiDnsPacket function in avahi-core/socket.c in avahi-daemon in
Avahi 0.6.16 and 0.6.25 allows remote attackers to cause a denial of
service (assertion failure and daemon exit) via a DNS packet with an
invalid checksum followed by a DNS packet with a valid checksum, a
different vulnerability than CVE-2008-5081 (CVE-2010-2244).

Packages for 2009.0 are provided as of the Extended Maintenance
Program. Please visit this link to learn more:
http://store.mandriva.com/product_info.php?cPath=149&amp;products_id=4
90

The updated packages have been patched to correct this issue."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:avahi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:avahi-dnsconfd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:avahi-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:avahi-sharp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:avahi-sharp-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:avahi-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64avahi-client-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64avahi-client3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64avahi-common-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64avahi-common3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64avahi-compat-howl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64avahi-compat-howl0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64avahi-compat-libdns_sd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64avahi-compat-libdns_sd1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64avahi-core-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64avahi-core5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64avahi-core6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64avahi-glib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64avahi-glib1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64avahi-gobject-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64avahi-gobject0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64avahi-qt3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64avahi-qt3_1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64avahi-qt4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64avahi-qt4_1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64avahi-ui-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64avahi-ui1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libavahi-client-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libavahi-client3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libavahi-common-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libavahi-common3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libavahi-compat-howl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libavahi-compat-howl0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libavahi-compat-libdns_sd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libavahi-compat-libdns_sd1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libavahi-core-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libavahi-core5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libavahi-core6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libavahi-glib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libavahi-glib1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libavahi-gobject-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libavahi-gobject0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libavahi-qt3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libavahi-qt3_1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libavahi-qt4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libavahi-qt4_1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libavahi-ui-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libavahi-ui1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2009.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2009.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2010.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2010.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2009.0", reference:"avahi-0.6.23-1.3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"avahi-dnsconfd-0.6.23-1.3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"avahi-python-0.6.23-1.3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"avahi-sharp-0.6.23-1.3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"avahi-sharp-doc-0.6.23-1.3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"avahi-x11-0.6.23-1.3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64avahi-client-devel-0.6.23-1.3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64avahi-client3-0.6.23-1.3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64avahi-common-devel-0.6.23-1.3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64avahi-common3-0.6.23-1.3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64avahi-compat-howl-devel-0.6.23-1.3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64avahi-compat-howl0-0.6.23-1.3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64avahi-compat-libdns_sd-devel-0.6.23-1.3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64avahi-compat-libdns_sd1-0.6.23-1.3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64avahi-core-devel-0.6.23-1.3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64avahi-core5-0.6.23-1.3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64avahi-glib-devel-0.6.23-1.3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64avahi-glib1-0.6.23-1.3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64avahi-gobject-devel-0.6.23-1.3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64avahi-gobject0-0.6.23-1.3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64avahi-qt3-devel-0.6.23-1.3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64avahi-qt3_1-0.6.23-1.3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64avahi-qt4-devel-0.6.23-1.3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64avahi-qt4_1-0.6.23-1.3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64avahi-ui-devel-0.6.23-1.3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64avahi-ui1-0.6.23-1.3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libavahi-client-devel-0.6.23-1.3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libavahi-client3-0.6.23-1.3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libavahi-common-devel-0.6.23-1.3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libavahi-common3-0.6.23-1.3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libavahi-compat-howl-devel-0.6.23-1.3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libavahi-compat-howl0-0.6.23-1.3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libavahi-compat-libdns_sd-devel-0.6.23-1.3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libavahi-compat-libdns_sd1-0.6.23-1.3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libavahi-core-devel-0.6.23-1.3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libavahi-core5-0.6.23-1.3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libavahi-glib-devel-0.6.23-1.3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libavahi-glib1-0.6.23-1.3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libavahi-gobject-devel-0.6.23-1.3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libavahi-gobject0-0.6.23-1.3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libavahi-qt3-devel-0.6.23-1.3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libavahi-qt3_1-0.6.23-1.3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libavahi-qt4-devel-0.6.23-1.3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libavahi-qt4_1-0.6.23-1.3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libavahi-ui-devel-0.6.23-1.3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libavahi-ui1-0.6.23-1.3mdv2009.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2009.1", reference:"avahi-0.6.24-2.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"avahi-dnsconfd-0.6.24-2.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"avahi-python-0.6.24-2.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"avahi-sharp-0.6.24-2.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"avahi-sharp-doc-0.6.24-2.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"avahi-x11-0.6.24-2.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64avahi-client-devel-0.6.24-2.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64avahi-client3-0.6.24-2.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64avahi-common-devel-0.6.24-2.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64avahi-common3-0.6.24-2.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64avahi-compat-howl-devel-0.6.24-2.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64avahi-compat-howl0-0.6.24-2.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64avahi-compat-libdns_sd-devel-0.6.24-2.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64avahi-compat-libdns_sd1-0.6.24-2.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64avahi-core-devel-0.6.24-2.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64avahi-core6-0.6.24-2.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64avahi-glib-devel-0.6.24-2.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64avahi-glib1-0.6.24-2.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64avahi-gobject-devel-0.6.24-2.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64avahi-gobject0-0.6.24-2.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64avahi-qt3-devel-0.6.24-2.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64avahi-qt3_1-0.6.24-2.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64avahi-qt4-devel-0.6.24-2.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64avahi-qt4_1-0.6.24-2.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64avahi-ui-devel-0.6.24-2.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64avahi-ui1-0.6.24-2.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libavahi-client-devel-0.6.24-2.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libavahi-client3-0.6.24-2.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libavahi-common-devel-0.6.24-2.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libavahi-common3-0.6.24-2.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libavahi-compat-howl-devel-0.6.24-2.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libavahi-compat-howl0-0.6.24-2.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libavahi-compat-libdns_sd-devel-0.6.24-2.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libavahi-compat-libdns_sd1-0.6.24-2.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libavahi-core-devel-0.6.24-2.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libavahi-core6-0.6.24-2.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libavahi-glib-devel-0.6.24-2.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libavahi-glib1-0.6.24-2.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libavahi-gobject-devel-0.6.24-2.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libavahi-gobject0-0.6.24-2.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libavahi-qt3-devel-0.6.24-2.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libavahi-qt3_1-0.6.24-2.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libavahi-qt4-devel-0.6.24-2.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libavahi-qt4_1-0.6.24-2.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libavahi-ui-devel-0.6.24-2.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libavahi-ui1-0.6.24-2.1mdv2009.1", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2010.0", reference:"avahi-0.6.25-3.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"avahi-dnsconfd-0.6.25-3.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"avahi-python-0.6.25-3.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"avahi-sharp-0.6.25-3.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"avahi-sharp-doc-0.6.25-3.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"avahi-x11-0.6.25-3.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64avahi-client-devel-0.6.25-3.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64avahi-client3-0.6.25-3.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64avahi-common-devel-0.6.25-3.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64avahi-common3-0.6.25-3.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64avahi-compat-howl-devel-0.6.25-3.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64avahi-compat-howl0-0.6.25-3.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64avahi-compat-libdns_sd-devel-0.6.25-3.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64avahi-compat-libdns_sd1-0.6.25-3.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64avahi-core-devel-0.6.25-3.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64avahi-core6-0.6.25-3.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64avahi-glib-devel-0.6.25-3.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64avahi-glib1-0.6.25-3.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64avahi-gobject-devel-0.6.25-3.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64avahi-gobject0-0.6.25-3.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64avahi-qt3-devel-0.6.25-3.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64avahi-qt3_1-0.6.25-3.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64avahi-qt4-devel-0.6.25-3.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64avahi-qt4_1-0.6.25-3.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64avahi-ui-devel-0.6.25-3.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64avahi-ui1-0.6.25-3.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libavahi-client-devel-0.6.25-3.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libavahi-client3-0.6.25-3.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libavahi-common-devel-0.6.25-3.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libavahi-common3-0.6.25-3.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libavahi-compat-howl-devel-0.6.25-3.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libavahi-compat-howl0-0.6.25-3.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libavahi-compat-libdns_sd-devel-0.6.25-3.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libavahi-compat-libdns_sd1-0.6.25-3.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libavahi-core-devel-0.6.25-3.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libavahi-core6-0.6.25-3.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libavahi-glib-devel-0.6.25-3.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libavahi-glib1-0.6.25-3.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libavahi-gobject-devel-0.6.25-3.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libavahi-gobject0-0.6.25-3.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libavahi-qt3-devel-0.6.25-3.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libavahi-qt3_1-0.6.25-3.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libavahi-qt4-devel-0.6.25-3.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libavahi-qt4_1-0.6.25-3.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libavahi-ui-devel-0.6.25-3.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libavahi-ui1-0.6.25-3.1mdv2010.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2010.1", reference:"avahi-0.6.25-5.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"avahi-dnsconfd-0.6.25-5.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"avahi-python-0.6.25-5.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"avahi-sharp-0.6.25-5.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"avahi-sharp-doc-0.6.25-5.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"avahi-x11-0.6.25-5.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64avahi-client-devel-0.6.25-5.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64avahi-client3-0.6.25-5.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64avahi-common-devel-0.6.25-5.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64avahi-common3-0.6.25-5.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64avahi-compat-howl-devel-0.6.25-5.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64avahi-compat-howl0-0.6.25-5.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64avahi-compat-libdns_sd-devel-0.6.25-5.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64avahi-compat-libdns_sd1-0.6.25-5.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64avahi-core-devel-0.6.25-5.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64avahi-core6-0.6.25-5.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64avahi-glib-devel-0.6.25-5.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64avahi-glib1-0.6.25-5.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64avahi-gobject-devel-0.6.25-5.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64avahi-gobject0-0.6.25-5.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64avahi-qt3-devel-0.6.25-5.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64avahi-qt3_1-0.6.25-5.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64avahi-qt4-devel-0.6.25-5.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64avahi-qt4_1-0.6.25-5.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64avahi-ui-devel-0.6.25-5.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64avahi-ui1-0.6.25-5.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libavahi-client-devel-0.6.25-5.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libavahi-client3-0.6.25-5.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libavahi-common-devel-0.6.25-5.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libavahi-common3-0.6.25-5.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libavahi-compat-howl-devel-0.6.25-5.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libavahi-compat-howl0-0.6.25-5.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libavahi-compat-libdns_sd-devel-0.6.25-5.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libavahi-compat-libdns_sd1-0.6.25-5.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libavahi-core-devel-0.6.25-5.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libavahi-core6-0.6.25-5.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libavahi-glib-devel-0.6.25-5.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libavahi-glib1-0.6.25-5.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libavahi-gobject-devel-0.6.25-5.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libavahi-gobject0-0.6.25-5.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libavahi-qt3-devel-0.6.25-5.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libavahi-qt3_1-0.6.25-5.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libavahi-qt4-devel-0.6.25-5.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libavahi-qt4_1-0.6.25-5.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libavahi-ui-devel-0.6.25-5.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libavahi-ui1-0.6.25-5.1mdv2010.1", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
