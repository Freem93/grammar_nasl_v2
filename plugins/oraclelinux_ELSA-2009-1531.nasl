#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2009:1531 and 
# Oracle Linux Security Advisory ELSA-2009-1531 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(67949);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/12/07 20:57:51 $");

  script_cve_id("CVE-2009-0689", "CVE-2009-3274", "CVE-2009-3372", "CVE-2009-3373", "CVE-2009-3375", "CVE-2009-3376", "CVE-2009-3380", "CVE-2009-3384", "CVE-2009-3385");
  script_xref(name:"RHSA", value:"2009:1531");

  script_name(english:"Oracle Linux 3 / 4 : seamonkey (ELSA-2009-1531)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2009:1531 :

Updated SeaMonkey packages that fix several security issues are now
available for Red Hat Enterprise Linux 3 and 4.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

SeaMonkey is an open source Web browser, email and newsgroup client,
IRC chat client, and HTML editor.

A flaw was found in the way SeaMonkey creates temporary file names for
downloaded files. If a local attacker knows the name of a file
SeaMonkey is going to download, they can replace the contents of that
file with arbitrary contents. (CVE-2009-3274)

A heap-based buffer overflow flaw was found in the SeaMonkey string to
floating point conversion routines. A web page containing malicious
JavaScript could crash SeaMonkey or, potentially, execute arbitrary
code with the privileges of the user running SeaMonkey.
(CVE-2009-1563)

A flaw was found in the way SeaMonkey handles text selection. A
malicious website may be able to read highlighted text in a different
domain (e.g. another website the user is viewing), bypassing the
same-origin policy. (CVE-2009-3375)

A flaw was found in the way SeaMonkey displays a right-to-left
override character when downloading a file. In these cases, the name
displayed in the title bar differs from the name displayed in the
dialog body. An attacker could use this flaw to trick a user into
downloading a file that has a file name or extension that differs from
what the user expected. (CVE-2009-3376)

Several flaws were found in the processing of malformed web content. A
web page containing malicious content could cause SeaMonkey to crash
or, potentially, execute arbitrary code with the privileges of the
user running SeaMonkey. (CVE-2009-3380)

All SeaMonkey users should upgrade to these updated packages, which
correct these issues. After installing the update, SeaMonkey must be
restarted for the changes to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2009-October/001221.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2009-October/001222.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected seamonkey packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(16, 119, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:seamonkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:seamonkey-chat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:seamonkey-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:seamonkey-dom-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:seamonkey-js-debugger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:seamonkey-mail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:seamonkey-nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:seamonkey-nspr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:seamonkey-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:seamonkey-nss-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(3|4)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 3 / 4", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL3", cpu:"i386", reference:"seamonkey-1.0.9-0.47.0.1.el3")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"seamonkey-1.0.9-0.47.0.1.el3")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"seamonkey-chat-1.0.9-0.47.0.1.el3")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"seamonkey-chat-1.0.9-0.47.0.1.el3")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"seamonkey-devel-1.0.9-0.47.0.1.el3")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"seamonkey-devel-1.0.9-0.47.0.1.el3")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"seamonkey-dom-inspector-1.0.9-0.47.0.1.el3")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"seamonkey-dom-inspector-1.0.9-0.47.0.1.el3")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"seamonkey-js-debugger-1.0.9-0.47.0.1.el3")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"seamonkey-js-debugger-1.0.9-0.47.0.1.el3")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"seamonkey-mail-1.0.9-0.47.0.1.el3")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"seamonkey-mail-1.0.9-0.47.0.1.el3")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"seamonkey-nspr-1.0.9-0.47.0.1.el3")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"seamonkey-nspr-1.0.9-0.47.0.1.el3")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"seamonkey-nspr-devel-1.0.9-0.47.0.1.el3")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"seamonkey-nspr-devel-1.0.9-0.47.0.1.el3")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"seamonkey-nss-1.0.9-0.47.0.1.el3")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"seamonkey-nss-1.0.9-0.47.0.1.el3")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"seamonkey-nss-devel-1.0.9-0.47.0.1.el3")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"seamonkey-nss-devel-1.0.9-0.47.0.1.el3")) flag++;

if (rpm_check(release:"EL4", reference:"seamonkey-1.0.9-50.0.1.el4_8")) flag++;
if (rpm_check(release:"EL4", reference:"seamonkey-chat-1.0.9-50.0.1.el4_8")) flag++;
if (rpm_check(release:"EL4", reference:"seamonkey-devel-1.0.9-50.0.1.el4_8")) flag++;
if (rpm_check(release:"EL4", reference:"seamonkey-dom-inspector-1.0.9-50.0.1.el4_8")) flag++;
if (rpm_check(release:"EL4", reference:"seamonkey-js-debugger-1.0.9-50.0.1.el4_8")) flag++;
if (rpm_check(release:"EL4", reference:"seamonkey-mail-1.0.9-50.0.1.el4_8")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "seamonkey / seamonkey-chat / seamonkey-devel / etc");
}
