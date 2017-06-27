#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0618 and 
# CentOS Errata and Security Advisory 2006:0618 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67036);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/01/27 00:45:19 $");

  script_cve_id("CVE-2006-3918");
  script_bugtraq_id(19661);
  script_osvdb_id(27487, 27488);
  script_xref(name:"RHSA", value:"2006:0618");

  script_name(english:"CentOS 4 : apache (CESA-2006:0618)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated Apache httpd packages that correct a security issue are now
available for Red Hat Enterprise Linux 2.1.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The Apache HTTP Server is a popular Web server available for free.

A bug was found in Apache where an invalid Expect header sent to the
server was returned to the user in an unescaped error message. This
could allow an attacker to perform a cross-site scripting attack if a
victim was tricked into connecting to a site and sending a carefully
crafted Expect header. (CVE-2006-3918)

While a web browser cannot be forced to send an arbitrary Expect
header by a third-party attacker, it was recently discovered that
certain versions of the Flash plugin can manipulate request headers.
If users running such versions can be persuaded to load a web page
with a malicious Flash applet, a cross-site scripting attack against
the server may be possible.

Users of Apache should upgrade to these updated packages, which
contain a backported patch to correct this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-August/013165.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fd734734"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected apache packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:httpd-suexec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/08/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/05/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"httpd-2.0.52-28.ent.centos4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"httpd-devel-2.0.52-28.ent.centos4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"httpd-manual-2.0.52-28.ent.centos4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"httpd-suexec-2.0.52-28.ent.centos4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"mod_ssl-2.0.52-28.ent.centos4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
