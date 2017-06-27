#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1185. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(40440);
  script_version ("$Revision: 1.19 $");
  script_cvs_date("$Date: 2017/01/03 17:27:02 $");

  script_cve_id("CVE-2009-2404");
  script_osvdb_id(56724);
  script_xref(name:"RHSA", value:"2009:1185");

  script_name(english:"RHEL 3 : seamonkey (RHSA-2009:1185)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated SeaMonkey packages that fix a security issue are now available
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
    value:"https://www.redhat.com/security/data/cve/CVE-2009-2404.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2009-1185.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:seamonkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:seamonkey-chat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:seamonkey-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:seamonkey-dom-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:seamonkey-js-debugger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:seamonkey-mail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:seamonkey-nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:seamonkey-nspr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:seamonkey-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:seamonkey-nss-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2017 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^3([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 3.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2009:1185";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL3", reference:"seamonkey-1.0.9-0.41.el3")) flag++;
  if (rpm_check(release:"RHEL3", reference:"seamonkey-chat-1.0.9-0.41.el3")) flag++;
  if (rpm_check(release:"RHEL3", reference:"seamonkey-devel-1.0.9-0.41.el3")) flag++;
  if (rpm_check(release:"RHEL3", reference:"seamonkey-dom-inspector-1.0.9-0.41.el3")) flag++;
  if (rpm_check(release:"RHEL3", reference:"seamonkey-js-debugger-1.0.9-0.41.el3")) flag++;
  if (rpm_check(release:"RHEL3", reference:"seamonkey-mail-1.0.9-0.41.el3")) flag++;
  if (rpm_check(release:"RHEL3", reference:"seamonkey-nspr-1.0.9-0.41.el3")) flag++;
  if (rpm_check(release:"RHEL3", reference:"seamonkey-nspr-devel-1.0.9-0.41.el3")) flag++;
  if (rpm_check(release:"RHEL3", reference:"seamonkey-nss-1.0.9-0.41.el3")) flag++;
  if (rpm_check(release:"RHEL3", reference:"seamonkey-nss-devel-1.0.9-0.41.el3")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "seamonkey / seamonkey-chat / seamonkey-devel / etc");
  }
}
