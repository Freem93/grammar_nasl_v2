#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0214 and 
# CentOS Errata and Security Advisory 2008:0214 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(31947);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/05/19 23:34:18 $");

  script_cve_id("CVE-2007-6239", "CVE-2008-1612");
  script_bugtraq_id(28693);
  script_xref(name:"RHSA", value:"2008:0214");

  script_name(english:"CentOS 3 / 4 / 5 : squid (CESA-2008:0214)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated squid packages that fix a security issue are now available for
Red Hat Enterprise Linux 2.1, 3, 4 and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Squid is a high-performance proxy caching server for Web clients,
supporting FTP, gopher, and HTTP data objects.

A flaw was found in the way squid manipulated HTTP headers for cached
objects stored in system memory. An attacker could use this flaw to
cause a squid child process to exit. This interrupted existing
connections and made proxy services unavailable. Note: the parent
squid process started a new child process, so this attack only
resulted in a temporary denial of service. (CVE-2008-1612)

Users of squid are advised to upgrade to these updated packages, which
contain a backported patch to resolve this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-April/014809.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8bdb6d6e"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-April/014810.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7ad24876"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-April/014812.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?89f8b9d1"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-April/014813.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?45ed70ce"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-April/014818.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7c501af2"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-April/014819.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3c197189"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-April/014830.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?aad15677"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-April/014831.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?52102e51"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected squid package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:squid");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/04/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-3", reference:"squid-2.5.STABLE3-9.3E")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"squid-2.5.STABLE14-1.4E.el4_6.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"squid-2.5.STABLE14-1.4E.c4.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"squid-2.5.STABLE14-1.4E.el4_6.2")) flag++;

if (rpm_check(release:"CentOS-5", reference:"squid-2.6.STABLE6-5.el5_1.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
