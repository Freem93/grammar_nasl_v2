#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2007:082. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(25033);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2013/06/01 00:01:19 $");

  script_cve_id("CVE-2005-4835", "CVE-2006-7177", "CVE-2006-7178", "CVE-2006-7179", "CVE-2006-7180");
  script_xref(name:"MDKSA", value:"2007:082");

  script_name(english:"Mandrake Linux Security Advisory : madwifi-source (MDKSA-2007:082)");
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
"The ath_rate_sample function in the ath_rate/sample/sample.c sample
code in MadWifi before 0.9.3 allows remote attackers to cause a denial
of service (failed KASSERT and system crash) by moving a connected
system to a location with low signal strength, and possibly other
vectors related to a race condition between interface enabling and
packet transmission. (CVE-2005-4835)

MadWifi, when Ad-Hoc mode is used, allows remote attackers to cause a
denial of service (system crash) via unspecified vectors that lead to
a kernel panic in the ieee80211_input function, related to packets
coming from a malicious WinXP system. (CVE-2006-7177)

MadWifi before 0.9.3 does not properly handle reception of an AUTH
frame by an IBSS node, which allows remote attackers to cause a denial
of service (system crash) via a certain AUTH frame. (CVE-2006-7178)

ieee80211_input.c in MadWifi before 0.9.3 does not properly process
Channel Switch Announcement Information Elements (CSA IEs), which
allows remote attackers to cause a denial of service (loss of
communication) via a Channel Switch Count less than or equal to one,
triggering a channel change. (CVE-2006-7179)

ieee80211_output.c in MadWifi before 0.9.3 sends unencrypted packets
before WPA authentication succeeds, which allows remote attackers to
obtain sensitive information (related to network structure), and
possibly cause a denial of service (disrupted authentication) and
conduct spoofing attacks. (CVE-2006-7180)

Updated packages have been updated to 0.9.3 to correct this issue.
Wpa_supplicant is built using madwifi-source and has been rebuilt
using 0.9.3 source."
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected madwifi-source, wpa_gui and / or wpa_supplicant
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:madwifi-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:wpa_gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:wpa_supplicant");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2007");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2007.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/04/12");
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
if (rpm_check(release:"MDK2007.0", reference:"madwifi-source-0.9.3-1.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"wpa_gui-0.5.5-2.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"wpa_supplicant-0.5.5-2.1mdv2007.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2007.1", reference:"madwifi-source-0.9.3-1.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"wpa_gui-0.5.7-1.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"wpa_supplicant-0.5.7-1.1mdv2007.1", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
