#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2004:674. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(16039);
  script_version ("$Revision: 1.11 $");
  script_cvs_date("$Date: 2014/05/02 17:31:16 $");

  script_cve_id("CVE-2004-1152");
  script_osvdb_id(12397);
  script_xref(name:"RHSA", value:"2004:674");

  script_name(english:"RHEL 3 : acroread (RHSA-2004:674)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated Adobe Acrobat Reader package that fixes a security issue is
now available.

The Adobe Acrobat Reader browser allows for the viewing, distributing,
and printing of documents in portable document format (PDF).

iDEFENSE has reported that Adobe Acrobat Reader 5.0.9 contains a
buffer overflow when decoding email messages. An attacker could create
a malicious PDF file which could execute arbitrary code if opened by a
victim. The Common Vulnerabilities and Exposures project has assigned
the name CVE-2004-1152 to this issue.

All users of Acrobat Reader are advised to upgrade to this updated
package, which contains Acrobat Reader version 5.0.10 which is not
vulnerable to this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-1152.html"
  );
  # http://www.idefense.com/application/poi/display?id=161&type=vulnerabilities&
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cd6783cb"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2004-674.html"
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

  script_set_attribute(attribute:"patch_publication_date", value:"2004/12/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/12/23");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/12/14");
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
if (rpm_check(release:"RHEL3", cpu:"i386", reference:"acroread-5.10-0.EL3")) flag++;
if (rpm_check(release:"RHEL3", cpu:"i386", reference:"acroread-plugin-5.10-0.EL3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
