#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0200 and 
# CentOS Errata and Security Advisory 2006:0200 respectively.
#

include("compat.inc");

if (description)
{
  script_id(21983);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/03/22 14:32:16 $");

  script_cve_id("CVE-2005-4134", "CVE-2006-0292", "CVE-2006-0296");
  script_osvdb_id(21533, 22890, 22892, 22894, 79168, 79169);
  script_xref(name:"RHSA", value:"2006:0200");

  script_name(english:"CentOS 4 : firefox (CESA-2006:0200)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated firefox package that fixes several security bugs is now
available.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

Mozilla Firefox is an open source Web browser.

Igor Bukanov discovered a bug in the way Firefox's JavaScript
interpreter dereferences objects. If a user visits a malicious web
page, Firefox could crash or execute arbitrary code as the user
running Firefox. The Common Vulnerabilities and Exposures project
assigned the name CVE-2006-0292 to this issue.

moz_bug_r_a4 discovered a bug in Firefox's XULDocument.persist()
function. A malicious web page could inject arbitrary RDF data into a
user's localstore.rdf file, which can cause Firefox to execute
arbitrary JavaScript when a user runs Firefox. (CVE-2006-0296)

A denial of service bug was found in the way Firefox saves history
information. If a user visits a web page with a very long title, it is
possible Firefox will crash or take a very long time the next time it
is run. (CVE-2005-4134)

This update also fixes a bug when using XSLT to transform documents.
Passing DOM Nodes as parameters to functions expecting an xsl:param
could cause Firefox to throw an exception.

Users of Firefox are advised to upgrade to this updated package, which
contains backported patches to correct these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-February/012614.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?263c83c2"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-February/012623.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a68eb42b"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-February/012624.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e5800764"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firefox package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:firefox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/02/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/05");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/12/07");
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
if (rpm_check(release:"CentOS-4", reference:"firefox-1.0.7-1.4.3.centos4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
