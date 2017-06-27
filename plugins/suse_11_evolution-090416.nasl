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
  script_id(41386);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2013/10/25 23:41:53 $");

  script_cve_id("CVE-2009-0582");

  script_name(english:"SuSE 11 Security Update : Evolution (SAT Patch Number 778)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"camel's NTLM SASL authentication mechanism as used by evolution did
not properly validate server's challenge packets. (CVE-2009-0582)

This update also includes the following non-security fixes :

  - Fixes a critical crasher in mailer component.

  - Fixes creation of recurrence monthly items in GroupWise.

  - Includes fixes for some usability issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=419303"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=475541"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=477697"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=479908"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=480091"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=484213"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-0582.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 778.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:evolution");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:evolution-data-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:evolution-data-server-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:evolution-data-server-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:evolution-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:evolution-pilot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:gtkhtml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:gtkhtml2-lang");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"evolution-2.24.1.1-15.8.4")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"evolution-data-server-2.24.1.1-11.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"evolution-data-server-lang-2.24.1.1-11.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"evolution-lang-2.24.1.1-15.8.4")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"evolution-pilot-2.24.1.1-15.8.4")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"gtkhtml2-3.24.1.1-3.23.2")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"gtkhtml2-lang-3.24.1.1-3.23.2")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"evolution-2.24.1.1-15.8.4")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"evolution-data-server-2.24.1.1-11.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"evolution-data-server-32bit-2.24.1.1-11.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"evolution-data-server-lang-2.24.1.1-11.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"evolution-lang-2.24.1.1-15.8.4")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"evolution-pilot-2.24.1.1-15.8.4")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"gtkhtml2-3.24.1.1-3.23.2")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"gtkhtml2-lang-3.24.1.1-3.23.2")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"evolution-data-server-2.24.1.1-11.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"evolution-data-server-lang-2.24.1.1-11.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"gtkhtml2-3.24.1.1-3.23.2")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"gtkhtml2-lang-3.24.1.1-3.23.2")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"s390x", reference:"evolution-data-server-32bit-2.24.1.1-11.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"evolution-data-server-32bit-2.24.1.1-11.8.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
