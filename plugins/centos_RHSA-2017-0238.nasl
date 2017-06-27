#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:0238 and 
# CentOS Errata and Security Advisory 2017:0238 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(96962);
  script_version("$Revision: 3.5 $");
  script_cvs_date("$Date: 2017/03/15 21:22:53 $");

  script_cve_id("CVE-2017-5373", "CVE-2017-5375", "CVE-2017-5376", "CVE-2017-5378", "CVE-2017-5380", "CVE-2017-5383", "CVE-2017-5390", "CVE-2017-5396");
  script_osvdb_id(150831, 150832, 150834, 150836, 150837, 150858, 150859, 150860, 150861, 150862, 150863, 150864, 150865, 150866, 150875, 150878);
  script_xref(name:"RHSA", value:"2017:0238");

  script_name(english:"CentOS 5 / 6 / 7 : thunderbird (CESA-2017:0238)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for thunderbird is now available for Red Hat Enterprise
Linux 5, Red Hat Enterprise Linux 6, and Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Mozilla Thunderbird is a standalone mail and newsgroup client.

This update upgrades Thunderbird to version 45.7.0.

Security Fix(es) :

* Multiple flaws were found in the processing of malformed web
content. A web page containing malicious content could cause
Thunderbird to crash or, potentially, execute arbitrary code with the
privileges of the user running Thunderbird. (CVE-2017-5373,
CVE-2017-5375, CVE-2017-5376, CVE-2017-5378, CVE-2017-5380,
CVE-2017-5383, CVE-2017-5390, CVE-2017-5396)

Red Hat would like to thank the Mozilla project for reporting these
issues. Upstream acknowledges Jann Horn, Filipe Gomes, Nils, Armin
Razmjou, Christian Holler, Gary Kwong, Andre Bargull, Jan de Mooij,
Tom Schuster, Oriol, Rh0, Nicolas Gregoire, and Jerri Rice as the
original reporters."
  );
  # http://lists.centos.org/pipermail/centos-announce/2017-February/022262.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ae062c96"
  );
  # http://lists.centos.org/pipermail/centos-announce/2017-February/022263.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?22fd62af"
  );
  # http://lists.centos.org/pipermail/centos-announce/2017-February/022264.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6ae52bec"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected thunderbird package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"thunderbird-45.7.0-1.el5.centos")) flag++;

if (rpm_check(release:"CentOS-6", reference:"thunderbird-45.7.0-1.el6.centos")) flag++;

if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"thunderbird-45.7.0-1.el7.centos")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
