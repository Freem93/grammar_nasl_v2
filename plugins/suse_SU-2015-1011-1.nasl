#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:1011-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(84016);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2015/09/29 14:15:33 $");

  script_osvdb_id(123116, 123117);

  script_name(english:"SUSE SLED11 / SLES11 Security Update : cups (SUSE-SU-2015:1011-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes a privilege escalation via cross-site scripting and
bad print job submission used to replace cupsd.conf on the server.
This combination of issues could lead to remote code execution.

CERT-VU-810572 has been assigned to this issue.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/924208"
  );
  # https://download.suse.com/patch/finder/?keywords=cfe8bb7d17a9116bd37d397cd41c000f
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?47085e50"
  );
  # https://www.suse.com/support/update/announcement/2015/suse-su-20151011-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d51595b4"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 11 SP3 :

zypper in -t patch sdksp3-cups=10707

SUSE Linux Enterprise Server 11 SP3 for VMware :

zypper in -t patch slessp3-cups=10707

SUSE Linux Enterprise Server 11 SP3 :

zypper in -t patch slessp3-cups=10707

SUSE Linux Enterprise Desktop 11 SP3 :

zypper in -t patch sledsp3-cups=10707

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cups-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cups-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = eregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! ereg(pattern:"^(SLED11|SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED11 / SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! ereg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP3", os_ver + " SP" + sp);
if (os_ver == "SLED11" && (! ereg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLED11 SP3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"cups-libs-32bit-1.3.9-8.46.56.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"s390x", reference:"cups-libs-32bit-1.3.9-8.46.56.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"cups-1.3.9-8.46.56.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"cups-client-1.3.9-8.46.56.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"cups-libs-1.3.9-8.46.56.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"cups-1.3.9-8.46.56.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"cups-client-1.3.9-8.46.56.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"cups-libs-1.3.9-8.46.56.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"cups-libs-32bit-1.3.9-8.46.56.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"cups-1.3.9-8.46.56.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"cups-client-1.3.9-8.46.56.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"cups-libs-1.3.9-8.46.56.1")) flag++;


if (flag)
{
  set_kb_item(name:'www/0/XSS', value:TRUE);
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cups");
}
