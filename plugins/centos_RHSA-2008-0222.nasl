#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0222 and 
# CentOS Errata and Security Advisory 2008:0222 respectively.
#

include("compat.inc");

if (description)
{
  script_id(31998);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/05/19 23:34:18 $");

  script_cve_id("CVE-2008-1380");
  script_bugtraq_id(28818);
  script_osvdb_id(44467);
  script_xref(name:"RHSA", value:"2008:0222");

  script_name(english:"CentOS 4 / 5 : firefox (CESA-2008:0222)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated firefox packages that fix a security bug are now available for
Red Hat Enterprise Linux 4 and 5.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

Mozilla Firefox is an open source Web browser.

A flaw was found in the processing of malformed JavaScript content. A
web page containing such malicious content could cause Firefox to
crash or, potentially, execute arbitrary code as the user running
Firefox. (CVE-2008-1380)

All Firefox users should upgrade to these updated packages, which
contain backported patches that correct these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-April/014834.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4790be61"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-April/014835.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?aab6fdfe"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-April/014837.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?31f9681f"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-April/014839.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fdbae838"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-April/014863.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9a784c63"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firefox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:firefox-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/04/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/04/22");
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
if (rpm_check(release:"CentOS-4", reference:"firefox-1.5.0.12-0.15.el4.centos")) flag++;

if (rpm_check(release:"CentOS-5", reference:"firefox-1.5.0.12-15.el5.centos")) flag++;
if (rpm_check(release:"CentOS-5", reference:"firefox-devel-1.5.0.12-15.el5.centos")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
