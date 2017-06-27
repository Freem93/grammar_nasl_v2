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
  script_id(51628);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2013/10/25 23:52:02 $");

  script_cve_id("CVE-2010-3609");

  script_name(english:"SuSE 11.1 Security Update : openSLP (SAT Patch Number 3312)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The openslp daemon could run into an endless loop when receiving
specially crafted packets (CVE-2010-3609). This has been fixed.

Additionally the following non-security bugs were fixed :

  - 564504: Fix handling of DA answers if both active and
    passive DA detection is off

  - 597215: Add configuration options to openSLP:
    net.slp.DASyncReg makes slpd query statically configured
    DAs for registrations, net.slp.isDABackup enables
    periodic writing of remote registrations to a backup
    file which is also read on startup. Both options can be
    used to decrease the time between the start of the slpd
    daemon and slpd knowing all registrations.

  - 601002: reduce CPU usage spikes on machines with many
    connections by using the kernel netlink interface
    instead of reading the /proc filesystem.

  - 626444: Standard compliance was fixed by stripping
    leading and trailing white spaces when doing string
    comparisons of scopes."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=564504"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=597215"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=601002"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=626444"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=642571"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3609.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 3312.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:openslp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:openslp-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:openslp-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/21");
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
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"openslp-1.2.0-172.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"openslp-1.2.0-172.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"openslp-32bit-1.2.0-172.15.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"openslp-1.2.0-172.15.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"openslp-server-1.2.0-172.15.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"s390x", reference:"openslp-32bit-1.2.0-172.15.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"openslp-32bit-1.2.0-172.15.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
