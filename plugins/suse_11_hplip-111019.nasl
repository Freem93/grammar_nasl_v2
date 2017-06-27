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
  script_id(57107);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/10/25 23:46:54 $");

  script_cve_id("CVE-2011-2722");

  script_name(english:"SuSE 11.1 Security Update : hplip (SAT Patch Number 5307)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update provides an update of hplip to version 3.11.10 :

  - Fixed insecure tmp file handling in hpcupsfax.cpp
    CVE-2011-2722 see
    https://bugs.launchpad.net/hplip/+bug/809904.
    (bnc#704608)

  - New tech classes for HP OfficeJet Pro 8100, HP Deskjet
    3070 B611 series and HP Photosmart 7510 e-All-in-One.

  - Added new subtech class for HP Photosmart 6510
    e-All-in-one.

  - Modified the error message which was displayed in case
    of missing .asc file for manual plug-in install.

  - Several more supported printers and all-in-one devices.

  - Several bug fixies. For details see
    http://hplipopensource.com/hplip-web/release_notes.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=704608"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-2722.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 5307.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:hplip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:hplip-hpijs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/19");
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
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"hplip-3.11.10-0.6.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"hplip-hpijs-3.11.10-0.6.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"hplip-3.11.10-0.6.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"hplip-hpijs-3.11.10-0.6.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"hplip-3.11.10-0.6.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"hplip-hpijs-3.11.10-0.6.7.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
