#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0909 and 
# CentOS Errata and Security Advisory 2011:0909 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67085);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/04 14:39:51 $");

  script_cve_id("CVE-2009-4492", "CVE-2010-0541", "CVE-2011-0188", "CVE-2011-1004", "CVE-2011-1005");
  script_bugtraq_id(37710, 40895, 46458, 46460, 46966);
  script_osvdb_id(70957, 70958);
  script_xref(name:"RHSA", value:"2011:0909");

  script_name(english:"CentOS 5 : ruby (CESA-2011:0909)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated ruby packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Ruby is an extensible, interpreted, object-oriented, scripting
language. It has features to process text files and to do system
management tasks.

A flaw was found in the way large amounts of memory were allocated on
64-bit systems when using the BigDecimal class. A context-dependent
attacker could use this flaw to cause memory corruption, causing a
Ruby application that uses the BigDecimal class to crash or, possibly,
execute arbitrary code. This issue did not affect 32-bit systems.
(CVE-2011-0188)

A race condition flaw was found in the remove system entries method in
the FileUtils module. If a local user ran a Ruby script that uses this
method, a local attacker could use this flaw to delete arbitrary files
and directories accessible to that user via a symbolic link attack.
(CVE-2011-1004)

It was found that WEBrick (the Ruby HTTP server toolkit) did not
filter terminal escape sequences from its log files. A remote attacker
could use specially crafted HTTP requests to inject terminal escape
sequences into the WEBrick log files. If a victim viewed the log files
with a terminal emulator, it could result in control characters being
executed with the privileges of that user. (CVE-2009-4492)

A cross-site scripting (XSS) flaw was found in the way WEBrick
displayed error pages. A remote attacker could use this flaw to
perform a cross-site scripting attack against victims by tricking them
into visiting a specially crafted URL. (CVE-2010-0541)

A flaw was found in the method for translating an exception message
into a string in the Exception class. A remote attacker could use this
flaw to bypass safe level 4 restrictions, allowing untrusted (tainted)
code to modify arbitrary, trusted (untainted) strings, which safe
level 4 restrictions would otherwise prevent. (CVE-2011-1005)

Red Hat would like to thank Drew Yao of Apple Product Security for
reporting the CVE-2011-0188 and CVE-2010-0541 issues.

All Ruby users should upgrade to these updated packages, which contain
backported patches to resolve these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-June/017635.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bbd878e3"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-June/017636.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8d0e3ead"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected ruby packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-mode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-rdoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-ri");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-tcltk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"ruby-1.8.5-19.el5_6.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"ruby-devel-1.8.5-19.el5_6.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"ruby-docs-1.8.5-19.el5_6.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"ruby-irb-1.8.5-19.el5_6.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"ruby-libs-1.8.5-19.el5_6.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"ruby-mode-1.8.5-19.el5_6.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"ruby-rdoc-1.8.5-19.el5_6.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"ruby-ri-1.8.5-19.el5_6.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"ruby-tcltk-1.8.5-19.el5_6.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
