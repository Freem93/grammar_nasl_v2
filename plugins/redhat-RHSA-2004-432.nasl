#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2004:432. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(14380);
  script_version ("$Revision: 1.14 $");
  script_cvs_date("$Date: 2014/05/02 17:31:16 $");

  script_cve_id("CVE-2004-0630", "CVE-2004-0631");
  script_osvdb_id(8654, 8655);
  script_xref(name:"RHSA", value:"2004:432");

  script_name(english:"RHEL 3 : acroread (RHSA-2004:432)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated Adobe Acrobat Reader package that fixes multiple security
issues is now available.

The Adobe Acrobat Reader browser allows for the viewing, distributing,
and printing of documents in portable document format (PDF).

iDEFENSE has reported that Adobe Acrobat Reader 5.0 contains a buffer
overflow when decoding uuencoded documents. An attacker could execute
arbitrary code on a victim's machine if a user opens a specially
crafted uuencoded document. This issue poses the threat of remote
execution, since Acrobat Reader may be the default handler for PDF
files. The Common Vulnerabilities and Exposures project has assigned
the name CVE-2004-0631 to this issue.

iDEFENSE also reported that Adobe Acrobat Reader 5.0 contains an input
validation error in its uuencoding feature. An attacker could create a
file with a specially crafted file name which could lead to arbitrary
command execution on a victim's machine. The Common Vulnerabilities
and Exposures project has assigned the name CVE-2004-0630 to this
issue.

All users of Acrobat Reader are advised to upgrade to this updated
package, which is not vulnerable to these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-0630.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-0631.html"
  );
  # http://www.idefense.com/application/poi/display?id=125&type=vulnerabilities
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7aa457ea"
  );
  # http://www.idefense.com/application/poi/display?id=124&type=vulnerabilities
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?09112fc9"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2004-432.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected acroread and / or acroread-plugin packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:acroread");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:acroread-plugin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/08/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/26");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/08/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"RHEL3", cpu:"i386", reference:"acroread-5.09-1")) flag++;
if (rpm_check(release:"RHEL3", cpu:"i386", reference:"acroread-plugin-5.09-1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
