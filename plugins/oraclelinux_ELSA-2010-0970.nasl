#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2010:0970 and 
# Oracle Linux Security Advisory ELSA-2010-0970 respectively.
#

include("compat.inc");

if (description)
{
  script_id(68160);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/12/01 16:57:58 $");

  script_cve_id("CVE-2010-4344");
  script_bugtraq_id(45308);
  script_osvdb_id(69685);
  script_xref(name:"RHSA", value:"2010:0970");

  script_name(english:"Oracle Linux 4 / 5 : exim (ELSA-2010-0970)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2010:0970 :

Updated exim packages that fix one security issue are now available
for Red Hat Enterprise Linux 4 and 5, and Red Hat Enterprise Linux
4.7, 5.3, and 5.4 Extended Update Support.

The Red Hat Security Response Team has rated this update as having
critical security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

Exim is a mail transport agent (MTA) developed at the University of
Cambridge for use on Unix systems connected to the Internet.

A buffer overflow flaw was discovered in Exim's internal
string_vformat() function. A remote attacker could use this flaw to
execute arbitrary code on the mail server running Exim.
(CVE-2010-4344)

Note: successful exploitation would allow a remote attacker to execute
arbitrary code as root on a Red Hat Enterprise Linux 4 or 5 system
that is running the Exim mail server. An exploit for this issue is
known to exist.

For additional information regarding this flaw, along with mitigation
advice, please see the Knowledge Base article linked to in the
References section of this advisory.

Users of Exim are advised to update to these erratum packages which
contain a backported patch to correct this issue. After installing
this update, the Exim daemon will be restarted automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2010-December/001767.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2010-December/001768.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected exim packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Exim4 string_format Function Heap Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:exim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:exim-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:exim-mon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:exim-sa");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^(4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 4 / 5", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL4", reference:"exim-4.43-1.RHEL4.5.el4_8.1")) flag++;
if (rpm_check(release:"EL4", reference:"exim-doc-4.43-1.RHEL4.5.el4_8.1")) flag++;
if (rpm_check(release:"EL4", reference:"exim-mon-4.43-1.RHEL4.5.el4_8.1")) flag++;
if (rpm_check(release:"EL4", reference:"exim-sa-4.43-1.RHEL4.5.el4_8.1")) flag++;

if (rpm_check(release:"EL5", reference:"exim-4.63-5.el5_5.2")) flag++;
if (rpm_check(release:"EL5", reference:"exim-mon-4.63-5.el5_5.2")) flag++;
if (rpm_check(release:"EL5", reference:"exim-sa-4.63-5.el5_5.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "exim / exim-doc / exim-mon / exim-sa");
}
