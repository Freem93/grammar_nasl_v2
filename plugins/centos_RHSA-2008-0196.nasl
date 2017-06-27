#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0196 and 
# CentOS Errata and Security Advisory 2008:0196 respectively.
#

include("compat.inc");

if (description)
{
  script_id(31610);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2013/06/28 23:45:06 $");

  script_cve_id("CVE-2008-0888");
  script_bugtraq_id(28288);
  script_osvdb_id(43332);
  script_xref(name:"RHSA", value:"2008:0196");

  script_name(english:"CentOS 3 : unzip (CESA-2008:0196)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated unzip packages that fix a security issue are now available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The unzip utility is used to list, test, or extract files from a zip
archive.

An invalid pointer flaw was found in unzip. If a user ran unzip on a
specially crafted file, an attacker could execute arbitrary code with
that user's privileges. (CVE-2008-0888)

Red Hat would like to thank Tavis Ormandy of the Google Security Team
for reporting this issue.

All unzip users are advised to upgrade to these updated packages,
which contain a backported patch to resolve this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-March/014756.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c755adda"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-March/014757.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fdaf6609"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-March/014772.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7d83f0c5"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected unzip package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:unzip");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/03/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/03/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2013 Tenable Network Security, Inc.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/CentOS/release")) audit(AUDIT_OS_NOT, "CentOS");
if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", reference:"unzip-5.50-36.EL3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
