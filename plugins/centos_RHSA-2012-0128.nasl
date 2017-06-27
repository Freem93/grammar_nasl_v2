#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0128 and 
# CentOS Errata and Security Advisory 2012:0128 respectively.
#

include("compat.inc");

if (description)
{
  script_id(57960);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2014/08/16 19:09:24 $");

  script_cve_id("CVE-2011-3607", "CVE-2011-3639", "CVE-2011-4317", "CVE-2012-0031", "CVE-2012-0053");
  script_bugtraq_id(50494, 50802, 51407, 51706, 51869);
  script_osvdb_id(76744, 77310, 77444, 78293, 78556);
  script_xref(name:"RHSA", value:"2012:0128");

  script_name(english:"CentOS 6 : httpd (CESA-2012:0128)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated httpd packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The Apache HTTP Server is a popular web server.

It was discovered that the fix for CVE-2011-3368 (released via
RHSA-2011:1391) did not completely address the problem. An attacker
could bypass the fix and make a reverse proxy connect to an arbitrary
server not directly accessible to the attacker by sending an HTTP
version 0.9 request, or by using a specially crafted URI.
(CVE-2011-3639, CVE-2011-4317)

The httpd server included the full HTTP header line in the default
error page generated when receiving an excessively long or malformed
header. Malicious JavaScript running in the server's domain context
could use this flaw to gain access to httpOnly cookies.
(CVE-2012-0053)

An integer overflow flaw, leading to a heap-based buffer overflow, was
found in the way httpd performed substitutions in regular expressions.
An attacker able to set certain httpd settings, such as a user
permitted to override the httpd configuration for a specific directory
using a '.htaccess' file, could use this flaw to crash the httpd child
process or, possibly, execute arbitrary code with the privileges of
the 'apache' user. (CVE-2011-3607)

A flaw was found in the way httpd handled child process status
information. A malicious program running with httpd child process
privileges (such as a PHP or CGI script) could use this flaw to cause
the parent httpd process to crash during httpd service shutdown.
(CVE-2012-0031)

All httpd users should upgrade to these updated packages, which
contain backported patches to correct these issues. After installing
the updated packages, the httpd daemon will be restarted
automatically."
  );
  # http://lists.centos.org/pipermail/centos-announce/2012-February/018433.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?151c9269"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected httpd packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-14-410");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:httpd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/16");
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
if (rpm_check(release:"CentOS-6", reference:"httpd-2.2.15-15.el6.centos.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"httpd-devel-2.2.15-15.el6.centos.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"httpd-manual-2.2.15-15.el6.centos.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"httpd-tools-2.2.15-15.el6.centos.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"mod_ssl-2.2.15-15.el6.centos.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
