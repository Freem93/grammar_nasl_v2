#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0021. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63836);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/01/10 18:05:23 $");

  script_cve_id("CVE-2006-5857", "CVE-2007-0045", "CVE-2007-0046");
  script_osvdb_id(31046, 31048, 31316);
  script_xref(name:"RHSA", value:"2007:0021");

  script_name(english:"RHEL 3 : Adobe Acrobat Reader (RHSA-2007:0021)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated acroread packages that fix several security issues are now
available for Red Hat Enterprise Linux 3.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

[Updated 23 Jan 2007] The previous acroread packages were missing
dependencies on the new libraries which could prevent acroread from
starting. Replacement acroread packages have been added to this
erratum to correct this issue.

The Adobe Reader allows users to view and print documents in portable
document format (PDF).

A cross site scripting flaw was found in the way the Adobe Reader
Plugin processes certain malformed URLs. A malicious web page could
inject arbitrary javascript into the browser session which could
possibly lead to a cross site scripting attack. (CVE-2007-0045)

Two arbitrary code execution flaws were found in the way Adobe Reader
processes malformed document files. It may be possible to execute
arbitrary code on a victim's machine if the victim opens a malicious
PDF file. (CVE-2006-5857, CVE-2007-0046)

Please note that Adobe Reader 7.0.9 requires versions of several
system libraries that were not shipped with Red Hat Enterprise Linux
3. This update contains additional packages that provide the required
system library versions for Adobe Reader. These additional packages
are only required by Adobe Reader and do not replace or affect any
other aspects of a Red Hat Enterprise Linux 3 system.

All users of Adobe Reader are advised to upgrade to these updated
packages, which contain Adobe Reader version 7.0.9 and additional
libraries to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2006-5857.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-0045.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-0046.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.adobe.com/support/security/bulletins/apsb07-01.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2007-0021.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:acroread");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:acroread-libs-atk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:acroread-libs-glib2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:acroread-libs-gtk2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:acroread-libs-gtk2-engines");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:acroread-libs-pango");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:acroread-plugin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/12/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

flag = 0;
if (rpm_check(release:"RHEL3", cpu:"i386", reference:"acroread-7.0.9-1.1.1.EL3")) flag++;
if (rpm_check(release:"RHEL3", cpu:"i386", reference:"acroread-libs-atk-1.8.0-1.el3")) flag++;
if (rpm_check(release:"RHEL3", cpu:"i386", reference:"acroread-libs-glib2-2.4.7-1")) flag++;
if (rpm_check(release:"RHEL3", cpu:"i386", reference:"acroread-libs-gtk2-2.4.13-1.el3")) flag++;
if (rpm_check(release:"RHEL3", cpu:"i386", reference:"acroread-libs-gtk2-engines-2.2.0-1.el3")) flag++;
if (rpm_check(release:"RHEL3", cpu:"i386", reference:"acroread-libs-pango-1.6.0-1.el3")) flag++;
if (rpm_check(release:"RHEL3", cpu:"i386", reference:"acroread-plugin-7.0.9-1.1.1.EL3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
