#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0062 and 
# CentOS Errata and Security Advisory 2012:0062 respectively.
#

include("compat.inc");

if (description)
{
  script_id(57732);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/08/16 19:09:24 $");

  script_cve_id("CVE-2010-2642", "CVE-2011-0433", "CVE-2011-0764", "CVE-2011-1552", "CVE-2011-1553", "CVE-2011-1554");
  script_bugtraq_id(45678, 46941, 47168, 47169);
  script_osvdb_id(70302, 72302, 74526, 74527, 74528, 74729);
  script_xref(name:"RHSA", value:"2012:0062");

  script_name(english:"CentOS 6 : t1lib (CESA-2012:0062)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated t1lib packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The t1lib library allows you to rasterize bitmaps from PostScript Type
1 fonts.

Two heap-based buffer overflow flaws were found in the way t1lib
processed Adobe Font Metrics (AFM) files. If a specially crafted font
file was opened by an application linked against t1lib, it could cause
the application to crash or, potentially, execute arbitrary code with
the privileges of the user running the application. (CVE-2010-2642,
CVE-2011-0433)

An invalid pointer dereference flaw was found in t1lib. A specially
crafted font file could, when opened, cause an application linked
against t1lib to crash or, potentially, execute arbitrary code with
the privileges of the user running the application. (CVE-2011-0764)

A use-after-free flaw was found in t1lib. A specially crafted font
file could, when opened, cause an application linked against t1lib to
crash or, potentially, execute arbitrary code with the privileges of
the user running the application. (CVE-2011-1553)

An off-by-one flaw was found in t1lib. A specially crafted font file
could, when opened, cause an application linked against t1lib to crash
or, potentially, execute arbitrary code with the privileges of the
user running the application. (CVE-2011-1554)

An out-of-bounds memory read flaw was found in t1lib. A specially
crafted font file could, when opened, cause an application linked
against t1lib to crash. (CVE-2011-1552)

Red Hat would like to thank the Evince development team for reporting
CVE-2010-2642. Upstream acknowledges Jon Larimer of IBM X-Force as the
original reporter of CVE-2010-2642.

All users of t1lib are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. All
applications linked against t1lib must be restarted for this update to
take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2012-January/018395.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6f208486"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected t1lib packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:t1lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:t1lib-apps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:t1lib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:t1lib-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"t1lib-5.1.2-6.el6_2.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"t1lib-apps-5.1.2-6.el6_2.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"t1lib-devel-5.1.2-6.el6_2.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"t1lib-static-5.1.2-6.el6_2.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
