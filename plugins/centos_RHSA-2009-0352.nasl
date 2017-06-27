#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:0352 and 
# CentOS Errata and Security Advisory 2009:0352 respectively.
#

include("compat.inc");

if (description)
{
  script_id(43733);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/12/01 20:56:51 $");

  script_cve_id("CVE-2009-0586");
  script_bugtraq_id(34100);
  script_osvdb_id(52775);
  script_xref(name:"RHSA", value:"2009:0352");

  script_name(english:"CentOS 5 : gstreamer-plugins-base (CESA-2009:0352)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated gstreamer-plugins-base packages that fix a security issue are
now available for Red Hat Enterprise Linux 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

GStreamer is a streaming media framework based on graphs of filters
which operate on media data. GStreamer Base Plug-ins is a collection
of well-maintained base plug-ins.

An integer overflow flaw which caused a heap-based buffer overflow was
discovered in the Vorbis comment tags reader. An attacker could create
a carefully-crafted Vorbis file that would cause an application using
GStreamer to crash or, potentially, execute arbitrary code if opened
by a victim. (CVE-2009-0586)

All users of gstreamer-plugins-base are advised to upgrade to these
updated packages, which contain a backported patch to correct this
issue. After installing this update, all applications using GStreamer
(such as Totem or Rhythmbox) must be restarted for the changes to take
effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-April/015740.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8350d4c7"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-April/015741.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a75758c4"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gstreamer-plugins-base packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gstreamer-plugins-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gstreamer-plugins-base-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"gstreamer-plugins-base-0.10.20-3.0.1.el5_3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"gstreamer-plugins-base-devel-0.10.20-3.0.1.el5_3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
