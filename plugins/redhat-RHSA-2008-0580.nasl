#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0580. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(34953);
  script_version ("$Revision: 1.22 $");
  script_cvs_date("$Date: 2017/01/03 17:16:33 $");

  script_cve_id("CVE-2007-2953", "CVE-2008-2712", "CVE-2008-3074", "CVE-2008-3075", "CVE-2008-3076", "CVE-2008-4101", "CVE-2008-6235");
  script_bugtraq_id(25095);
  script_osvdb_id(38674, 46306, 51437, 52164);
  script_xref(name:"RHSA", value:"2008:0580");

  script_name(english:"RHEL 5 : vim (RHSA-2008:0580)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated vim packages that fix security issues are now available for
Red Hat Enterprise Linux 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Vim (Visual editor IMproved) is an updated and improved version of the
vi editor.

Several input sanitization flaws were found in Vim's keyword and tag
handling. If Vim looked up a document's maliciously crafted tag or
keyword, it was possible to execute arbitrary code as the user running
Vim. (CVE-2008-4101)

Multiple security flaws were found in netrw.vim, the Vim plug-in
providing file reading and writing over the network. If a user opened
a specially crafted file or directory with the netrw plug-in, it could
result in arbitrary code execution as the user running Vim.
(CVE-2008-3076)

A security flaw was found in zip.vim, the Vim plug-in that handles ZIP
archive browsing. If a user opened a ZIP archive using the zip.vim
plug-in, it could result in arbitrary code execution as the user
running Vim. (CVE-2008-3075)

A security flaw was found in tar.vim, the Vim plug-in which handles
TAR archive browsing. If a user opened a TAR archive using the tar.vim
plug-in, it could result in arbitrary code execution as the user
runnin Vim. (CVE-2008-3074)

Several input sanitization flaws were found in various Vim system
functions. If a user opened a specially crafted file, it was possible
to execute arbitrary code as the user running Vim. (CVE-2008-2712)

Ulf Harnhammar, of Secunia Research, discovered a format string flaw
in Vim's help tag processor. If a user was tricked into executing the
'helptags' command on malicious data, arbitrary code could be executed
with the permissions of the user running Vim. (CVE-2007-2953)

All Vim users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-2953.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-2712.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-3074.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-3075.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-4101.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-6235.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2008-0580.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 78, 94);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vim-X11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vim-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vim-enhanced");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vim-minimal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/11/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/11/25");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/07/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2008:0580";
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
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"vim-X11-7.0.109-4.el5_2.4z")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"vim-X11-7.0.109-4.el5_2.4z")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"vim-X11-7.0.109-4.el5_2.4z")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"vim-common-7.0.109-4.el5_2.4z")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"vim-common-7.0.109-4.el5_2.4z")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"vim-common-7.0.109-4.el5_2.4z")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"vim-enhanced-7.0.109-4.el5_2.4z")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"vim-enhanced-7.0.109-4.el5_2.4z")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"vim-enhanced-7.0.109-4.el5_2.4z")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"vim-minimal-7.0.109-4.el5_2.4z")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"vim-minimal-7.0.109-4.el5_2.4z")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"vim-minimal-7.0.109-4.el5_2.4z")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "vim-X11 / vim-common / vim-enhanced / vim-minimal");
  }
}
