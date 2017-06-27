#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:0476 and 
# CentOS Errata and Security Advisory 2009:0476 respectively.
#

include("compat.inc");

if (description)
{
  script_id(38721);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/05/19 23:43:06 $");

  script_cve_id("CVE-2009-1194");
  script_bugtraq_id(34870);
  script_osvdb_id(54279);
  script_xref(name:"RHSA", value:"2009:0476");

  script_name(english:"CentOS 3 / 4 / 5 : pango (CESA-2009:0476)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated pango and evolution28-pango packages that fix an integer
overflow flaw are now available for Red Hat Enterprise Linux 3, 4, and
5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

Pango is a library used for the layout and rendering of
internationalized text.

Will Drewry discovered an integer overflow flaw in Pango's
pango_glyph_string_set_size() function. If an attacker is able to pass
an arbitrarily long string to Pango, it may be possible to execute
arbitrary code with the permissions of the application calling Pango.
(CVE-2009-1194)

pango and evolution28-pango users are advised to upgrade to these
updated packages, which contain a backported patch to resolve this
issue. After installing this update, you must restart your system or
restart the X server for the update to take effect. Note: Restarting
the X server closes all open applications and logs you out of your
session."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2009-May/015847.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2009-May/015848.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2009-May/015853.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2009-May/015854.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2009-May/015860.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2009-May/015862.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2009-May/015928.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2009-May/015929.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected pango packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution28-pango");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution28-pango-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pango");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pango-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/05/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-3", reference:"pango-1.2.5-8")) flag++;
if (rpm_check(release:"CentOS-3", reference:"pango-devel-1.2.5-8")) flag++;

if (rpm_check(release:"CentOS-4", reference:"evolution28-pango-1.14.9-11.el4_7")) flag++;
if (rpm_check(release:"CentOS-4", reference:"evolution28-pango-devel-1.14.9-11.el4_7")) flag++;
if (rpm_check(release:"CentOS-4", reference:"pango-1.6.0-14.4_7")) flag++;
if (rpm_check(release:"CentOS-4", reference:"pango-devel-1.6.0-14.4_7")) flag++;

if (rpm_check(release:"CentOS-5", reference:"pango-1.14.9-5.el5.centos")) flag++;
if (rpm_check(release:"CentOS-5", reference:"pango-devel-1.14.9-5.el5.centos")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
