#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0153 and 
# CentOS Errata and Security Advisory 2010:0153 respectively.
#

include("compat.inc");

if (description)
{
  script_id(45361);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/12/05 14:31:49 $");

  script_cve_id("CVE-2009-0689", "CVE-2009-1571", "CVE-2009-2462", "CVE-2009-2463", "CVE-2009-2466", "CVE-2009-2470", "CVE-2009-3072", "CVE-2009-3075", "CVE-2009-3076", "CVE-2009-3077", "CVE-2009-3274", "CVE-2009-3376", "CVE-2009-3380", "CVE-2009-3979", "CVE-2010-0159");
  script_bugtraq_id(35765, 35769, 35776, 36343, 36851, 36852, 36867, 36871, 37361, 38286, 38287);
  script_osvdb_id(55603, 57972, 57976, 57977, 57978, 61091, 61186, 61187, 61188, 61189, 62402);
  script_xref(name:"RHSA", value:"2010:0153");

  script_name(english:"CentOS 5 : thunderbird (CESA-2010:0153)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote CentOS host is missing a security update which has been
documented in Red Hat advisory RHSA-2010:0153."
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-March/016584.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fa86cbd6"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-March/016585.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?90bbc466"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected thunderbird package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(16, 20, 94, 119, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/29");
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
if (rpm_check(release:"CentOS-5", reference:"thunderbird-2.0.0.24-2.el5.centos")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
