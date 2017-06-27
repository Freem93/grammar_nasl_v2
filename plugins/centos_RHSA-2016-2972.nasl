#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:2972 and 
# CentOS Errata and Security Advisory 2016:2972 respectively.
#

include("compat.inc");

if (description)
{
  script_id(96048);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2016/12/27 14:29:49 $");

  script_cve_id("CVE-2016-1248");
  script_osvdb_id(147697);
  script_xref(name:"RHSA", value:"2016:2972");

  script_name(english:"CentOS 6 / 7 : vim (CESA-2016:2972)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for vim is now available for Red Hat Enterprise Linux 6 and
Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Vim (Vi IMproved) is an updated and improved version of the vi editor.

Security Fix(es) :

* A vulnerability was found in vim in how certain modeline options
were treated. An attacker could craft a file that, when opened in vim
with modelines enabled, could execute arbitrary commands with
privileges of the user running vim. (CVE-2016-1248)"
  );
  # http://lists.centos.org/pipermail/centos-announce/2016-December/022185.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6bdcaf79"
  );
  # http://lists.centos.org/pipermail/centos-announce/2016-December/022187.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?011bb978"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected vim packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:vim-X11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:vim-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:vim-enhanced");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:vim-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:vim-minimal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-6", reference:"vim-X11-7.4.629-5.el6_8.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"vim-common-7.4.629-5.el6_8.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"vim-enhanced-7.4.629-5.el6_8.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"vim-filesystem-7.4.629-5.el6_8.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"vim-minimal-7.4.629-5.el6_8.1")) flag++;

if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"vim-X11-7.4.160-1.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"vim-common-7.4.160-1.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"vim-enhanced-7.4.160-1.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"vim-filesystem-7.4.160-1.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"vim-minimal-7.4.160-1.el7_3.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
