#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1000 and 
# CentOS Errata and Security Advisory 2011:1000 respectively.
#

include("compat.inc");

if (description)
{
  script_id(56262);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/12/18 14:26:56 $");

  script_cve_id("CVE-2010-3389");
  script_bugtraq_id(44359);
  script_osvdb_id(68808);
  script_xref(name:"RHSA", value:"2011:1000");

  script_name(english:"CentOS 5 : rgmanager (CESA-2011:1000)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote CentOS host is missing a security update which has been
documented in Red Hat advisory RHSA-2011:1000."
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-September/017958.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?797edea1"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-September/017959.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6c5a0b2a"
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2011-September/000132.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4f937158"
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2011-September/000133.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7164d185"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected rgmanager package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rgmanager");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"rgmanager-2.0.52-21.el5.centos")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
