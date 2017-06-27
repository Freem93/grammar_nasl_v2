#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2009:1185 and 
# Oracle Linux Security Advisory ELSA-2009-1185 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67903);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/12/01 16:41:04 $");

  script_cve_id("CVE-2009-2404");
  script_osvdb_id(56724);
  script_xref(name:"RHSA", value:"2009:1185");

  script_name(english:"Oracle Linux 3 : seamonkey (ELSA-2009-1185)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2009:1185 :

Updated SeaMonkey packages that fix a security issue are now available
for Red Hat Enterprise Linux 3.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

SeaMonkey is an open source Web browser, email and newsgroup client,
IRC chat client, and HTML editor.

Moxie Marlinspike reported a heap overflow flaw in a regular
expression parser in the NSS library (provided by SeaMonkey) used to
match common names in certificates. A malicious website could present
a carefully-crafted certificate in such a way as to trigger the heap
overflow, leading to a crash or, possibly, arbitrary code execution
with the permissions of the user running SeaMonkey. (CVE-2009-2404)

Note: in order to exploit this issue without further user interaction,
the carefully-crafted certificate would need to be signed by a
Certificate Authority trusted by SeaMonkey, otherwise SeaMonkey
presents the victim with a warning that the certificate is untrusted.
Only if the user then accepts the certificate will the overflow take
place.

All SeaMonkey users should upgrade to these updated packages, which
contain a backported patch to correct this issue. After installing the
updated packages, SeaMonkey must be restarted for the update to take
effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2009-July/001098.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected seamonkey packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(119);

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

  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/31");
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
if (! ereg(pattern:"^3([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 3", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL3", cpu:"i386", reference:"seamonkey-1.0.9-0.41.0.1.el3")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"seamonkey-1.0.9-0.41.0.1.el3")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"seamonkey-chat-1.0.9-0.41.0.1.el3")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"seamonkey-chat-1.0.9-0.41.0.1.el3")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"seamonkey-devel-1.0.9-0.41.0.1.el3")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"seamonkey-devel-1.0.9-0.41.0.1.el3")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"seamonkey-dom-inspector-1.0.9-0.41.0.1.el3")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"seamonkey-dom-inspector-1.0.9-0.41.0.1.el3")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"seamonkey-js-debugger-1.0.9-0.41.0.1.el3")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"seamonkey-js-debugger-1.0.9-0.41.0.1.el3")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"seamonkey-mail-1.0.9-0.41.0.1.el3")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"seamonkey-mail-1.0.9-0.41.0.1.el3")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"seamonkey-nspr-1.0.9-0.41.0.1.el3")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"seamonkey-nspr-1.0.9-0.41.0.1.el3")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"seamonkey-nspr-devel-1.0.9-0.41.0.1.el3")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"seamonkey-nspr-devel-1.0.9-0.41.0.1.el3")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"seamonkey-nss-1.0.9-0.41.0.1.el3")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"seamonkey-nss-1.0.9-0.41.0.1.el3")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"seamonkey-nss-devel-1.0.9-0.41.0.1.el3")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"seamonkey-nss-devel-1.0.9-0.41.0.1.el3")) flag++;


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
