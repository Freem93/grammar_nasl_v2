#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0494 and 
# CentOS Errata and Security Advisory 2007:0494 respectively.
#

include("compat.inc");

if (description)
{
  script_id(25502);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/05/26 15:53:26 $");

  script_cve_id("CVE-2007-2022");
  script_bugtraq_id(23437);
  script_osvdb_id(34140);
  script_xref(name:"RHSA", value:"2007:0494");

  script_name(english:"CentOS 3 / 4 / 5 : kdebase (CESA-2007:0494)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kdebase packages that resolve an interaction security issue
with Adobe Flash Player are now available.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The kdebase packages provide the core applications for KDE, the K
Desktop Environment. These core packages include Konqueror, the web
browser and file manager.

A problem with the interaction between the Flash Player and the
Konqueror web browser was found. The problem could lead to key presses
leaking to the Flash Player applet instead of the browser
(CVE-2007-2022).

Users of Konqueror who have installed the Adobe Flash Player plugin
should upgrade to these updated packages, which contain a patch
provided by Dirk Muller that protects against this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-June/013923.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cf93834f"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-June/013924.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?490afe4e"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-June/013925.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?809ff984"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-June/013926.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?05274b19"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-June/013931.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?61a79bb3"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-June/013932.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?55c13fe2"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-June/013965.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?30db5052"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-June/013966.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?eaa77deb"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kdebase packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(200);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kdebase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kdebase-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/06/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/04/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-3", reference:"kdebase-3.1.3-5.16")) flag++;
if (rpm_check(release:"CentOS-3", reference:"kdebase-devel-3.1.3-5.16")) flag++;

if (rpm_check(release:"CentOS-4", reference:"kdebase-3.3.1-5.19.rhel4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"kdebase-devel-3.3.1-5.19.rhel4")) flag++;

if (rpm_check(release:"CentOS-5", reference:"kdebase-3.5.4-13.6.el5.centos")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kdebase-devel-3.5.4-13.6.el5.centos")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
