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
  script_id(41422);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2014/04/03 11:06:12 $");

  script_cve_id("CVE-2009-0368");

  script_name(english:"SuSE 11 Security Update : OpenSC (SAT Patch Number 641)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Private data objects on smartcards initialized with OpenSC could be
accessed without authentication. (CVE-2009-0368)

Only blank cards initialized with OpenSC are affected by this problem.
Affected cards need to be manually fixed, updating the opensc package
alone is not sufficient!

Please carefully read and follow the instructions on the following
website if you are using PIN protected private data objects on smart
cards other than Oberthur, and you have initialized those cards using
OpenSC: http://en.opensuse.org/Smart_Cards/Advisories"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=480262"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-0368.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 641.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_cwe_id(310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libopensc2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libopensc2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:opensc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:opensc-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/03/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2014 Tenable Network Security, Inc.");
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
if (pl) audit(AUDIT_OS_NOT, "SuSE 11.0");


flag = 0;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"libopensc2-0.11.6-5.25.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"opensc-0.11.6-5.25.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"libopensc2-0.11.6-5.25.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"libopensc2-32bit-0.11.6-5.25.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"opensc-0.11.6-5.25.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"opensc-32bit-0.11.6-5.25.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"libopensc2-0.11.6-5.25.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"opensc-0.11.6-5.25.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"s390x", reference:"libopensc2-32bit-0.11.6-5.25.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"s390x", reference:"opensc-32bit-0.11.6-5.25.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"libopensc2-32bit-0.11.6-5.25.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"opensc-32bit-0.11.6-5.25.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
