#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:761 and 
# CentOS Errata and Security Advisory 2005:761 respectively.
#

include("compat.inc");

if (description)
{
  script_id(21854);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/04 14:30:40 $");

  script_cve_id("CVE-2005-2491");
  script_bugtraq_id(14620);
  script_osvdb_id(18906);
  script_xref(name:"RHSA", value:"2005:761");

  script_name(english:"CentOS 3 / 4 : pcre (CESA-2005:761)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated pcre packages are now available to correct a security issue.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team

PCRE is a Perl-compatible regular expression library.

An integer overflow flaw was found in PCRE, triggered by a maliciously
crafted regular expression. On systems that accept arbitrary regular
expressions from untrusted users, this could be exploited to execute
arbitrary code with the privileges of the application using the
library. The Common Vulnerabilities and Exposures project assigned the
name CVE-2005-2491 to this issue.

The security impact of this issue varies depending on the way that
applications make use of PCRE. For example, the Apache web server uses
the system PCRE library in order to parse regular expressions, but
this flaw would only allow a user who already has the ability to write
.htaccess files to gain 'apache' privileges. For applications supplied
with Red Hat Enterprise Linux, a maximum security impact of moderate
has been assigned.

Users should update to these erratum packages that contain a
backported patch to correct this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-September/012129.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ce630608"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-September/012130.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?552bd5d3"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-September/012133.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?155183c5"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-September/012134.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4413cfa7"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-September/012139.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?49c2805a"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-September/012140.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?808ed201"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected pcre packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcre-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/03");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/08/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-3", reference:"pcre-3.9-10.2")) flag++;
if (rpm_check(release:"CentOS-3", reference:"pcre-devel-3.9-10.2")) flag++;

if (rpm_check(release:"CentOS-4", reference:"pcre-4.5-3.2.RHEL4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"pcre-devel-4.5-3.2.RHEL4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
