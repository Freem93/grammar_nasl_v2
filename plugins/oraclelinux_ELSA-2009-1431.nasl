#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2009:1431 and 
# Oracle Linux Security Advisory ELSA-2009-1431 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67923);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/12/07 20:57:51 $");

  script_cve_id("CVE-2009-2408", "CVE-2009-2409", "CVE-2009-2654", "CVE-2009-3072", "CVE-2009-3075", "CVE-2009-3076", "CVE-2009-3077");
  script_bugtraq_id(35803, 36343);
  script_osvdb_id(56723, 57972, 57976, 57977, 57978);
  script_xref(name:"RHSA", value:"2009:1431");

  script_name(english:"Oracle Linux 4 : seamonkey (ELSA-2009-1431)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2009:1431 :

Updated SeaMonkey packages that fix several security issues are now
available for Red Hat Enterprise Linux 4.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

SeaMonkey is an open source Web browser, email and newsgroup client,
IRC chat client, and HTML editor.

Several flaws were found in the processing of malformed web content. A
web page containing malicious content could cause SeaMonkey to crash
or, potentially, execute arbitrary code with the privileges of the
user running SeaMonkey. (CVE-2009-3072, CVE-2009-3075)

A use-after-free flaw was found in SeaMonkey. An attacker could use
this flaw to crash SeaMonkey or, potentially, execute arbitrary code
with the privileges of the user running SeaMonkey. (CVE-2009-3077)

Descriptions in the dialogs when adding and removing PKCS #11 modules
were not informative. An attacker able to trick a user into installing
a malicious PKCS #11 module could use this flaw to install their own
Certificate Authority certificates on a user's machine, making it
possible to trick the user into believing they are viewing a trusted
site or, potentially, execute arbitrary code with the privileges of
the user running SeaMonkey. (CVE-2009-3076)

A flaw was found in the way SeaMonkey displays the address bar when
window.open() is called in a certain way. An attacker could use this
flaw to conceal a malicious URL, possibly tricking a user into
believing they are viewing a trusted site. (CVE-2009-2654)

All SeaMonkey users should upgrade to these updated packages, which
correct these issues. After installing the update, SeaMonkey must be
restarted for the changes to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2009-September/001148.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected seamonkey packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 94, 310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:seamonkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:seamonkey-chat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:seamonkey-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:seamonkey-dom-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:seamonkey-js-debugger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:seamonkey-mail");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/10");
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
if (! ereg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 4", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL4", reference:"seamonkey-1.0.9-48.0.1.el4_8")) flag++;
if (rpm_check(release:"EL4", reference:"seamonkey-chat-1.0.9-48.0.1.el4_8")) flag++;
if (rpm_check(release:"EL4", reference:"seamonkey-devel-1.0.9-48.0.1.el4_8")) flag++;
if (rpm_check(release:"EL4", reference:"seamonkey-dom-inspector-1.0.9-48.0.1.el4_8")) flag++;
if (rpm_check(release:"EL4", reference:"seamonkey-js-debugger-1.0.9-48.0.1.el4_8")) flag++;
if (rpm_check(release:"EL4", reference:"seamonkey-mail-1.0.9-48.0.1.el4_8")) flag++;


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
