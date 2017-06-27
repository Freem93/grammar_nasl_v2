#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0011 and 
# CentOS Errata and Security Advisory 2007:0011 respectively.
#

include("compat.inc");

if (description)
{
  script_id(24024);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/04 14:30:40 $");

  script_cve_id("CVE-2006-4514");
  script_bugtraq_id(21358);
  script_osvdb_id(31702);
  script_xref(name:"RHSA", value:"2007:0011");

  script_name(english:"CentOS 3 / 4 : libgsf (CESA-2007:0011)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libgsf packages that fix a buffer overflow flaw are now
available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The GNOME Structured File Library is a utility library for reading and
writing structured file formats.

A heap based buffer overflow flaw was found in the way GNOME
Structured File Library processes and certain OLE documents. If an
person opened a specially crafted OLE file, it could cause the client
application to crash or execute arbitrary code. (CVE-2006-4514)

Users of GNOME Structured File Library should upgrade to these updated
packages, which contain a backported patch that resolves this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-January/013462.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?266105e2"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-January/013463.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e7b569ce"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-January/013465.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d343b4c6"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-January/013468.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?be3897a1"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-January/013474.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b8e70bb2"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-January/013475.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?50c18975"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libgsf packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libgsf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libgsf-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/01/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/01/17");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/11/30");
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
if (rpm_check(release:"CentOS-3", reference:"libgsf-1.6.0-7")) flag++;
if (rpm_check(release:"CentOS-3", reference:"libgsf-devel-1.6.0-7")) flag++;

if (rpm_check(release:"CentOS-4", reference:"libgsf-1.10.1-2")) flag++;
if (rpm_check(release:"CentOS-4", reference:"libgsf-devel-1.10.1-2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
