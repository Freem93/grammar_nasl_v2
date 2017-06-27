#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0164 and 
# CentOS Errata and Security Advisory 2006:0164 respectively.
#

include("compat.inc");

if (description)
{
  script_id(21887);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/05/19 23:25:25 $");

  script_cve_id("CVE-2005-3656");
  script_osvdb_id(22259);
  script_xref(name:"RHSA", value:"2006:0164");

  script_name(english:"CentOS 3 / 4 : mod_auth_pgsql (CESA-2006:0164)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated mod_auth_pgsql packages that fix format string security issues
are now available for Red Hat Enterprise Linux 3 and 4.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

The mod_auth_pgsql package is an httpd module that allows user
authentication against information stored in a PostgreSQL database.

Several format string flaws were found in the way mod_auth_pgsql logs
information. It may be possible for a remote attacker to execute
arbitrary code as the 'apache' user if mod_auth_pgsql is used for user
authentication. The Common Vulnerabilities and Exposures project
assigned the name CVE-2005-3656 to this issue.

Please note that this issue only affects servers which have
mod_auth_pgsql installed and configured to perform user authentication
against a PostgreSQL database.

All users of mod_auth_pgsql should upgrade to these updated packages,
which contain a backported patch to resolve this issue.

This issue does not affect the mod_auth_pgsql package supplied with
Red Hat Enterprise Linux 2.1.

Red Hat would like to thank iDefense for reporting this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-January/012547.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f510bdd6"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-January/012548.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5031321e"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-January/012551.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b7146279"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-January/012552.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f2a7474d"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-January/012553.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ddbfce26"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-January/012554.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9a340477"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mod_auth_pgsql package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mod_auth_pgsql");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/01/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/03");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/01/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-3", reference:"mod_auth_pgsql-2.0.1-4.ent.1")) flag++;

if (rpm_check(release:"CentOS-4", reference:"mod_auth_pgsql-2.0.1-7.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
