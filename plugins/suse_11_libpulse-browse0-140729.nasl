#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from SuSE 11 update information. The text itself is
# copyright (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(77179);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/08/13 14:28:38 $");

  script_cve_id("CVE-2014-3970");

  script_name(english:"SuSE 11.3 Security Update : pulseaudio (SAT Patch Number 9568)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The following security issue is fixed in this update :

  - Fixed a remote denial of service attack in
    module-rtp-recv. (CVE-2014-3970)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=881524"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-3970.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 9568.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libpulse-browse0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libpulse-mainloop-glib0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libpulse0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libpulse0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:pulseaudio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:pulseaudio-esound-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:pulseaudio-gdm-hooks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:pulseaudio-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:pulseaudio-module-bluetooth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:pulseaudio-module-gconf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:pulseaudio-module-jack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:pulseaudio-module-lirc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:pulseaudio-module-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:pulseaudio-module-zeroconf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:pulseaudio-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (isnull(pl) || int(pl) != 3) audit(AUDIT_OS_NOT, "SuSE 11.3");


flag = 0;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libpulse-browse0-0.9.23-0.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libpulse-mainloop-glib0-0.9.23-0.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libpulse0-0.9.23-0.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"pulseaudio-0.9.23-0.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"pulseaudio-esound-compat-0.9.23-0.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"pulseaudio-gdm-hooks-0.9.23-0.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"pulseaudio-lang-0.9.23-0.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"pulseaudio-module-bluetooth-0.9.23-0.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"pulseaudio-module-gconf-0.9.23-0.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"pulseaudio-module-jack-0.9.23-0.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"pulseaudio-module-lirc-0.9.23-0.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"pulseaudio-module-x11-0.9.23-0.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"pulseaudio-module-zeroconf-0.9.23-0.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"pulseaudio-utils-0.9.23-0.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libpulse-browse0-0.9.23-0.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libpulse-mainloop-glib0-0.9.23-0.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libpulse0-0.9.23-0.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libpulse0-32bit-0.9.23-0.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"pulseaudio-0.9.23-0.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"pulseaudio-esound-compat-0.9.23-0.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"pulseaudio-gdm-hooks-0.9.23-0.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"pulseaudio-lang-0.9.23-0.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"pulseaudio-module-bluetooth-0.9.23-0.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"pulseaudio-module-gconf-0.9.23-0.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"pulseaudio-module-jack-0.9.23-0.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"pulseaudio-module-lirc-0.9.23-0.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"pulseaudio-module-x11-0.9.23-0.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"pulseaudio-module-zeroconf-0.9.23-0.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"pulseaudio-utils-0.9.23-0.15.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"libpulse-browse0-0.9.23-0.15.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"libpulse-mainloop-glib0-0.9.23-0.15.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"libpulse0-0.9.23-0.15.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"pulseaudio-0.9.23-0.15.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"pulseaudio-esound-compat-0.9.23-0.15.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"pulseaudio-gdm-hooks-0.9.23-0.15.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"pulseaudio-lang-0.9.23-0.15.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"pulseaudio-module-x11-0.9.23-0.15.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"pulseaudio-module-zeroconf-0.9.23-0.15.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"pulseaudio-utils-0.9.23-0.15.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"libpulse0-32bit-0.9.23-0.15.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"libpulse0-32bit-0.9.23-0.15.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
