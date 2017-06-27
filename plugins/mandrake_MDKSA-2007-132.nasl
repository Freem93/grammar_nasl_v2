#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2007:132. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(25598);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2013/06/01 00:01:20 $");

  script_cve_id("CVE-2007-2829", "CVE-2007-2830", "CVE-2007-2831");
  script_xref(name:"MDKSA", value:"2007:132");

  script_name(english:"Mandrake Linux Security Advisory : madwifi-source (MDKSA-2007:132)");
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
"The 802.11 network stack in MadWifi prior to 0.9.3.1 would alloa
remote attackers to cause a denial of service (system hang) via a
crafted length field in nested 802.3 Ethernet frames in Fast Frame
packets, which results in a NULL pointer dereference (CVE-2007-2829).

The ath_beacon_config function in MadWifi prior to 0.9.3.1 would allow
a remote attacker to cause a denial of service (system crash) via
crafted beacon interval information when scanning for access points,
which triggered a divide-by-zero error (CVE-2007-2830).

An array index error in MadWifi prior to 0.9.3.1 would allow a local
user to cause a denial of service (system crash) and possibly obtain
kerenl memory contents, as well as possibly allowing for the execution
of arbitrary code via a large negative array index value
(CVE-2007-2831).

Updated packages have been updated to 0.9.3.1 to correct these issues.
Wpa_supplicant is built using madwifi-source and has been rebuilt
using 0.9.3.1 source."
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected madwifi-source, wpa_gui and / or wpa_supplicant
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:madwifi-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:wpa_gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:wpa_supplicant");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2007");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2007.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/06/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/06/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2007.0", reference:"madwifi-source-0.9.3.1-1.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"wpa_gui-0.5.5-2.2mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"wpa_supplicant-0.5.5-2.2mdv2007.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2007.1", reference:"madwifi-source-0.9.3.1-1.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"wpa_gui-0.5.7-1.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"wpa_supplicant-0.5.7-1.2mdv2007.1", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
