#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2007:0722 and 
# Oracle Linux Security Advisory ELSA-2007-0722 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(67546);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/06 16:53:46 $");

  script_cve_id("CVE-2007-3089", "CVE-2007-3656", "CVE-2007-3734", "CVE-2007-3735", "CVE-2007-3736", "CVE-2007-3737", "CVE-2007-3738");
  script_bugtraq_id(24946);
  script_osvdb_id(27974, 27975, 28843, 28844, 28845, 28846, 28847, 28848, 29013, 38000, 38001, 38002, 38010, 38015, 38016, 38024, 38028, 94476, 94477, 94478, 94479, 94480, 95338, 95339, 95340, 95341, 95911, 95912, 95913, 95914, 95915, 96645);
  script_xref(name:"RHSA", value:"2007:0722");

  script_name(english:"Oracle Linux 3 / 4 : seamonkey (ELSA-2007-0722)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2007:0722 :

Updated SeaMonkey packages that fix several security bugs are now
available for Red Hat Enterprise Linux 2.1, 3, and 4.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

SeaMonkey is an open source Web browser, advanced email and newsgroup
client, IRC chat client, and HTML editor.

Several flaws were found in the way SeaMonkey processed certain
malformed JavaScript code. A web page containing malicious JavaScript
code could cause SeaMonkey to crash or potentially execute arbitrary
code as the user running SeaMonkey. (CVE-2007-3734, CVE-2007-3735,
CVE-2007-3737, CVE-2007-3738)

Several content injection flaws were found in the way SeaMonkey
handled certain JavaScript code. A web page containing malicious
JavaScript code could inject arbitrary content into other web pages.
(CVE-2007-3736, CVE-2007-3089)

A flaw was found in the way SeaMonkey cached web pages on the local
disk. A malicious web page may be able to inject arbitrary HTML into a
browsing session if the user reloads a targeted site. (CVE-2007-3656)

Users of SeaMonkey are advised to upgrade to these erratum packages,
which contain backported patches that correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2007-July/000270.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2007-July/000274.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected seamonkey packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(200);

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

  script_set_attribute(attribute:"patch_publication_date", value:"2007/07/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/08/12");
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
if (rpm_check(release:"EL3", cpu:"i386", reference:"seamonkey-1.0.9-0.3.el3.0.1")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"seamonkey-1.0.9-0.3.el3.0.1")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"seamonkey-chat-1.0.9-0.3.el3.0.1")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"seamonkey-chat-1.0.9-0.3.el3.0.1")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"seamonkey-devel-1.0.9-0.3.el3.0.1")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"seamonkey-devel-1.0.9-0.3.el3.0.1")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"seamonkey-dom-inspector-1.0.9-0.3.el3.0.1")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"seamonkey-dom-inspector-1.0.9-0.3.el3.0.1")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"seamonkey-js-debugger-1.0.9-0.3.el3.0.1")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"seamonkey-js-debugger-1.0.9-0.3.el3.0.1")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"seamonkey-mail-1.0.9-0.3.el3.0.1")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"seamonkey-mail-1.0.9-0.3.el3.0.1")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"seamonkey-nspr-1.0.9-0.3.el3.0.1")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"seamonkey-nspr-1.0.9-0.3.el3.0.1")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"seamonkey-nspr-devel-1.0.9-0.3.el3.0.1")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"seamonkey-nspr-devel-1.0.9-0.3.el3.0.1")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"seamonkey-nss-1.0.9-0.3.el3.0.1")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"seamonkey-nss-1.0.9-0.3.el3.0.1")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"seamonkey-nss-devel-1.0.9-0.3.el3.0.1")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"seamonkey-nss-devel-1.0.9-0.3.el3.0.1")) flag++;

if (rpm_check(release:"EL4", cpu:"i386", reference:"seamonkey-1.0.9-4.el4.0.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"seamonkey-1.0.9-4.el4.0.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"seamonkey-chat-1.0.9-4.el4.0.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"seamonkey-chat-1.0.9-4.el4.0.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"seamonkey-devel-1.0.9-4.el4.0.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"seamonkey-devel-1.0.9-4.el4.0.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"seamonkey-dom-inspector-1.0.9-4.el4.0.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"seamonkey-dom-inspector-1.0.9-4.el4.0.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"seamonkey-js-debugger-1.0.9-4.el4.0.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"seamonkey-js-debugger-1.0.9-4.el4.0.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"seamonkey-mail-1.0.9-4.el4.0.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"seamonkey-mail-1.0.9-4.el4.0.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"seamonkey-nspr-1.0.9-4.el4.0.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"seamonkey-nspr-1.0.9-4.el4.0.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"seamonkey-nspr-devel-1.0.9-4.el4.0.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"seamonkey-nspr-devel-1.0.9-4.el4.0.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"seamonkey-nss-1.0.9-4.el4.0.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"seamonkey-nss-1.0.9-4.el4.0.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"seamonkey-nss-devel-1.0.9-4.el4.0.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"seamonkey-nss-devel-1.0.9-4.el4.0.1")) flag++;


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
