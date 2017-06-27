#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:1551 and 
# CentOS Errata and Security Advisory 2016:1551 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(92703);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2016/11/17 21:12:11 $");

  script_cve_id("CVE-2016-2830", "CVE-2016-2836", "CVE-2016-2837", "CVE-2016-2838", "CVE-2016-5252", "CVE-2016-5254", "CVE-2016-5258", "CVE-2016-5259", "CVE-2016-5262", "CVE-2016-5263", "CVE-2016-5264", "CVE-2016-5265");
  script_osvdb_id(142419, 142420, 142421, 142422, 142423, 142424, 142425, 142426, 142468, 142474, 142476, 142478, 142479, 142480, 142481, 142482, 142484, 142485, 142486);
  script_xref(name:"RHSA", value:"2016:1551");

  script_name(english:"CentOS 5 / 6 / 7 : firefox (CESA-2016:1551)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for firefox is now available for Red Hat Enterprise Linux 5,
Red Hat Enterprise Linux 6, and Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Critical. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Mozilla Firefox is an open source web browser.

This update upgrades Firefox to version 45.3.0 ESR.

Security Fix(es) :

* Multiple flaws were found in the processing of malformed web
content. A web page containing malicious content could cause Firefox
to crash or, potentially, execute arbitrary code with the privileges
of the user running Firefox. (CVE-2016-2836, CVE-2016-5258,
CVE-2016-5259, CVE-2016-5252, CVE-2016-5263, CVE-2016-2830,
CVE-2016-2838, CVE-2016-5254, CVE-2016-5262, CVE-2016-5264,
CVE-2016-5265, CVE-2016-2837)

Red Hat would like to thank the Mozilla project for reporting these
issues. Upstream acknowledges Looben Yang, Carsten Book, Christian
Holler, Gary Kwong, Jesse Ruderman, Andrew McCreight, Phil Ringnalda,
Philipp, Toni Huttunen, Georg Koppen, Abhishek Arya, Atte Kettunen,
Nils, Nikita Arykov, and Abdulrahman Alqabandi as the original
reporters."
  );
  # http://lists.centos.org/pipermail/centos-announce/2016-August/022023.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ff6d41ab"
  );
  # http://lists.centos.org/pipermail/centos-announce/2016-August/022024.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?87b11ec0"
  );
  # http://lists.centos.org/pipermail/centos-announce/2016-August/022026.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?27b44c64"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firefox package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:firefox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/04");
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
if (rpm_check(release:"CentOS-5", reference:"firefox-45.3.0-1.el5.centos")) flag++;

if (rpm_check(release:"CentOS-6", reference:"firefox-45.3.0-1.el6.centos")) flag++;

if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"firefox-45.3.0-1.el7.centos")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");