#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:2237 and 
# CentOS Errata and Security Advisory 2015:2237 respectively.
#

include("compat.inc");

if (description)
{
  script_id(87145);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/04/28 18:15:07 $");

  script_cve_id("CVE-2015-2675");
  script_osvdb_id(119124);
  script_xref(name:"RHSA", value:"2015:2237");

  script_name(english:"CentOS 7 : rest (CESA-2015:2237)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated rest packages that fix one security issue are now available
for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having Low security
impact. A Common Vulnerability Scoring System (CVSS) base score, which
gives a detailed severity rating, is available from the CVE link in
the References section.

The rest library was designed to make it easier to access web services
that claim to be RESTful. A RESTful service should have URLs that
represent remote objects, which methods can then be called on.

It was found that the OAuth implementation in librest, a helper
library for RESTful services, incorrectly truncated the pointer
returned by the rest_proxy_call_get_url call. An attacker could use
this flaw to crash an application using the librest library.
(CVE-2015-2675)

All users of rest are advised to upgrade to these updated packages,
which contain a backported patch to correct this issue. After
installing the update, all applications using librest must be
restarted for the update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2015-November/002595.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ae727c6c"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected rest packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rest-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"rest-0.7.92-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"rest-devel-0.7.92-3.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
