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
  script_id(73751);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/05/12 10:42:05 $");

  script_cve_id("CVE-2014-1912");

  script_name(english:"SuSE 11.3 Security Update : Python (SAT Patch Number 9075)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Python was updated to fix a security issue in the socket.recvfrom_into
function, where data could be written over the end of the buffer.
(CVE-2014-1912)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=863741"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-1912.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 9075.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libpython2_6-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libpython2_6-1_0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:python-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:python-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:python-base-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:python-curses");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:python-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:python-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:python-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:python-doc-pdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:python-gdbm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:python-idle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:python-tk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:python-xml");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/29");
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
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libpython2_6-1_0-2.6.9-0.27.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"python-2.6.9-0.27.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"python-base-2.6.9-0.27.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"python-curses-2.6.9-0.27.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"python-devel-2.6.9-0.27.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"python-tk-2.6.9-0.27.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"python-xml-2.6.9-0.27.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libpython2_6-1_0-2.6.9-0.27.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libpython2_6-1_0-32bit-2.6.9-0.27.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"python-2.6.9-0.27.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"python-base-2.6.9-0.27.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"python-base-32bit-2.6.9-0.27.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"python-curses-2.6.9-0.27.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"python-devel-2.6.9-0.27.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"python-tk-2.6.9-0.27.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"python-xml-2.6.9-0.27.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"libpython2_6-1_0-2.6.9-0.27.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"python-2.6.9-0.27.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"python-base-2.6.9-0.27.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"python-curses-2.6.9-0.27.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"python-demo-2.6.9-0.27.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"python-doc-2.6-8.27.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"python-doc-pdf-2.6-8.27.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"python-gdbm-2.6.9-0.27.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"python-idle-2.6.9-0.27.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"python-tk-2.6.9-0.27.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"python-xml-2.6.9-0.27.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"libpython2_6-1_0-32bit-2.6.9-0.27.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"python-32bit-2.6.9-0.27.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"python-base-32bit-2.6.9-0.27.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"libpython2_6-1_0-32bit-2.6.9-0.27.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"python-32bit-2.6.9-0.27.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"python-base-32bit-2.6.9-0.27.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
