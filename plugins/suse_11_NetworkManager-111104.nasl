#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from SuSE 11 update information. The text itself is
# copyright (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57085);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/10/25 23:52:02 $");

  script_cve_id("CVE-2006-7246");

  script_name(english:"SuSE 11.1 Security Update : NetworkManager (SAT Patch Number 5381)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"NetworkManager did not pin a certificate's subject to an ESSID. A
rogue access point could therefore be used to conduct MITM attacks by
using any other valid certificate issued by same CA as used in the
original network (CVE-2006-7246). This has been fixed.

Please note that existing WPA2 Enterprise connections need to be
deleted and re-created to take advantage of the new security checks."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=574266"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=686093"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=694218"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2006-7246.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 5381.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:NetworkManager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:NetworkManager-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:NetworkManager-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:wpa_supplicant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:wpa_supplicant-gui");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2013 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)11") audit(AUDIT_OS_NOT, "SuSE 11");
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SuSE 11", cpu);

pl = get_kb_item("Host/SuSE/patchlevel");
if (isnull(pl) || int(pl) != 1) audit(AUDIT_OS_NOT, "SuSE 11.1");


flag = 0;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"NetworkManager-0.7.1_git20090811-3.9.9.5")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"NetworkManager-glib-0.7.1_git20090811-3.9.9.5")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"NetworkManager-gnome-0.7.1-5.15.7.5")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"wpa_supplicant-0.6.9-4.5.4")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"wpa_supplicant-gui-0.6.9-4.5.4")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"NetworkManager-0.7.1_git20090811-3.9.9.5")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"NetworkManager-glib-0.7.1_git20090811-3.9.9.5")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"NetworkManager-gnome-0.7.1-5.15.7.5")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"wpa_supplicant-0.6.9-4.5.4")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"wpa_supplicant-gui-0.6.9-4.5.4")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"NetworkManager-0.7.1_git20090811-3.9.9.5")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"NetworkManager-glib-0.7.1_git20090811-3.9.9.5")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"NetworkManager-gnome-0.7.1-5.15.7.5")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"wpa_supplicant-0.6.9-4.5.4")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"NetworkManager-0.7.1_git20090811-3.9.9.5")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"NetworkManager-glib-0.7.1_git20090811-3.9.9.5")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"NetworkManager-gnome-0.7.1-5.15.7.5")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"wpa_supplicant-0.6.9-4.5.4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
