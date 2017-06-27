#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:0021 and 
# CentOS Errata and Security Advisory 2017:0021 respectively.
#

include("compat.inc");

if (description)
{
  script_id(96342);
  script_version("$Revision: 3.3 $");
  script_cvs_date("$Date: 2017/01/23 15:31:52 $");

  script_cve_id("CVE-2016-9445", "CVE-2016-9809", "CVE-2016-9812", "CVE-2016-9813");
  script_osvdb_id(147530, 147995, 147996, 148099);
  script_xref(name:"RHSA", value:"2017:0021");

  script_name(english:"CentOS 7 : gstreamer1-plugins-bad-free (CESA-2017:0021)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for gstreamer1-plugins-bad-free is now available for Red Hat
Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

GStreamer is a streaming media framework based on graphs of filters
which operate on media data. The gstreamer1-plugins-bad-free package
contains a collection of plug-ins for GStreamer.

Security Fix(es) :

* An integer overflow flaw, leading to a heap-based buffer overflow,
was found in GStreamer's VMware VMnc video file format decoding
plug-in. A remote attacker could use this flaw to cause an application
using GStreamer to crash or, potentially, execute arbitrary code with
the privileges of the user running the application. (CVE-2016-9445)

* Multiple flaws were discovered in GStreamer's H.264 and MPEG-TS
plug-ins. A remote attacker could use these flaws to cause an
application using GStreamer to crash. (CVE-2016-9809, CVE-2016-9812,
CVE-2016-9813)"
  );
  # http://lists.centos.org/pipermail/centos-announce/2017-January/022194.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f075e171"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gstreamer1-plugins-bad-free packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gstreamer1-plugins-bad-free");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gstreamer1-plugins-bad-free-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/10");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gstreamer1-plugins-bad-free-1.4.5-6.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gstreamer1-plugins-bad-free-devel-1.4.5-6.el7_3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
