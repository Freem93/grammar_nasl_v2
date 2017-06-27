#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:575. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(18657);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2014/05/02 17:31:16 $");

  script_cve_id("CVE-2005-1625", "CVE-2005-1841");
  script_osvdb_id(17615, 17740);
  script_xref(name:"RHSA", value:"2005:575");
  script_xref(name:"Secunia", value:"14457");

  script_name(english:"RHEL 3 / 4 : Adobe Acrobat Reader (RHSA-2005:575)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated acroread packages that fix a security issue are now available.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

The Adobe Acrobat Reader browser allows for the viewing, distributing,
and printing of documents in portable document format (PDF).

A buffer overflow bug has been found in Adobe Acrobat Reader. It is
possible to execute arbitrary code on a victim's machine if the victim
is tricked into opening a malicious PDF file. The Common
Vulnerabilities and Exposures project has assigned the name
CVE-2005-1625 to this issue.

Please note that there is no browser plugin included with the x86_64
Adobe Acrobat Reader package; Therefore the security impact of this
issue on x86_64 is reduced from 'critical' to 'important'.

Additionally Secunia Research discovered a bug in the way Adobe
Acrobat Reader creates temporary files. When a user opens a document,
temporary files are created which may be world readable, allowing a
local user to view sensitive information. The Common Vulnerabilities
and Exposures project has assigned the name CVE-2005-1841 to this
issue.

All users of Acrobat Reader are advised to upgrade to these updated
packages, which contain Acrobat Reader version 7.0.0 and are not
vulnerable to this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-1625.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-1841.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.adobe.com/support/techdocs/329083.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2005-575.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected acroread and / or acroread-plugin packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:acroread");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:acroread-plugin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/07/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/10");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/06/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"RHEL3", cpu:"i386", reference:"acroread-7.0.0-4.1.0.EL3")) flag++;
if (rpm_check(release:"RHEL3", cpu:"i386", reference:"acroread-plugin-7.0.0-4.1.0.EL3")) flag++;

if (rpm_check(release:"RHEL4", cpu:"i386", reference:"acroread-7.0.0-4.2.0.EL4")) flag++;
if (rpm_check(release:"RHEL4", cpu:"i386", reference:"acroread-plugin-7.0.0-4.2.0.EL4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
