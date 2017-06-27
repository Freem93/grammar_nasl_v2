#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:2973 and 
# CentOS Errata and Security Advisory 2016:2973 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(96036);
  script_version("$Revision: 3.6 $");
  script_cvs_date("$Date: 2017/01/26 14:48:46 $");

  script_cve_id("CVE-2016-9893", "CVE-2016-9895", "CVE-2016-9899", "CVE-2016-9900", "CVE-2016-9901", "CVE-2016-9902", "CVE-2016-9905");
  script_osvdb_id(148666, 148667, 148668, 148693, 148695, 148696, 148697, 148698, 148699, 148700, 148701, 148706, 148707, 148708, 148709, 148710);
  script_xref(name:"RHSA", value:"2016:2973");

  script_name(english:"CentOS 5 / 6 / 7 : thunderbird (CESA-2016:2973)");
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

This update upgrades Thunderbird to version 45.6.0.

Security Fix(es) :

* Multiple flaws were found in the processing of malformed web
content. A web page containing malicious content could cause
Thunderbird to crash or, potentially, execute arbitrary code with the
privileges of the user running Thunderbird. (CVE-2016-9893,
CVE-2016-9899, CVE-2016-9895, CVE-2016-9900, CVE-2016-9901,
CVE-2016-9902, CVE-2016-9905)

Red Hat would like to thank the Mozilla project for reporting these
issues. Upstream acknowledges Wladimir Palant, Philipp, Andrew
Krasichkov, insertscript, Jan de Mooij, Iris Hsiao, Christian Holler,
Carsten Book, Timothy Nikkel, Christoph Diehl, Olli Pettay, Raymond
Forbes, and Boris Zbarsky as the original reporters."
  );
  # http://lists.centos.org/pipermail/centos-announce/2016-December/022183.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?95622ea3"
  );
  # http://lists.centos.org/pipermail/centos-announce/2016-December/022184.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?24b0bdcc"
  );
  # http://lists.centos.org/pipermail/centos-announce/2016-December/022186.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4076e67e"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected thunderbird package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"thunderbird-45.6.0-1.el5.centos")) flag++;

if (rpm_check(release:"CentOS-6", reference:"thunderbird-45.6.0-1.el6.centos")) flag++;

if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"thunderbird-45.6.0-1.el7.centos")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
