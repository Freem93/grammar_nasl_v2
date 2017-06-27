#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0199 and 
# CentOS Errata and Security Advisory 2006:0199 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(21891);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/05/19 23:25:25 $");

  script_cve_id("CVE-2005-4134", "CVE-2006-0292", "CVE-2006-0296");
  script_osvdb_id(21533, 22890, 22892, 79168, 79169);
  script_xref(name:"RHSA", value:"2006:0199");

  script_name(english:"CentOS 3 / 4 : mozilla (CESA-2006:0199)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated mozilla packages that fix several security bugs are now
available.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

Mozilla is an open source Web browser, advanced email and newsgroup
client, IRC chat client, and HTML editor.

Igor Bukanov discovered a bug in the way Mozilla's JavaScript
interpreter dereferences objects. If a user visits a malicious web
page, Mozilla could crash or execute arbitrary code as the user
running Mozilla. The Common Vulnerabilities and Exposures project
assigned the name CVE-2006-0292 to this issue.

moz_bug_r_a4 discovered a bug in Mozilla's XULDocument.persist()
function. A malicious web page could inject arbitrary RDF data into a
user's localstore.rdf file, which can cause Mozilla to execute
arbitrary JavaScript when a user runs Mozilla. (CVE-2006-0296)

A denial of service bug was found in the way Mozilla saves history
information. If a user visits a web page with a very long title, it is
possible Mozilla will crash or take a very long time the next time it
is run. (CVE-2005-4134)

Note that the Red Hat Enterprise Linux 3 packages also fix a bug when
using XSLT to transform documents. Passing DOM Nodes as parameters to
functions expecting an xsl:param could cause Mozilla to throw an
exception.

Users of Mozilla are advised to upgrade to these updated packages,
which contain backported patches to correct these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-February/012612.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2257fa71"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-February/012613.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c8231a77"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-February/012616.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c3b8a394"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-February/012617.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f709fdc5"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-February/012625.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?79d1c362"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-February/012626.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?42bf4387"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mozilla packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mozilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mozilla-chat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mozilla-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mozilla-dom-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mozilla-js-debugger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mozilla-mail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mozilla-nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mozilla-nspr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mozilla-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mozilla-nss-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/02/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/03");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/12/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-3", reference:"mozilla-1.7.12-1.1.3.4.centos3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"mozilla-chat-1.7.12-1.1.3.4.centos3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"mozilla-devel-1.7.12-1.1.3.4.centos3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"mozilla-dom-inspector-1.7.12-1.1.3.4.centos3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"mozilla-js-debugger-1.7.12-1.1.3.4.centos3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"mozilla-mail-1.7.12-1.1.3.4.centos3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"mozilla-nspr-1.7.12-1.1.3.4.centos3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"mozilla-nspr-devel-1.7.12-1.1.3.4.centos3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"mozilla-nss-1.7.12-1.1.3.4.centos3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"mozilla-nss-devel-1.7.12-1.1.3.4.centos3")) flag++;

if (rpm_check(release:"CentOS-4", reference:"mozilla-1.7.12-1.4.2.centos4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"mozilla-chat-1.7.12-1.4.2.centos4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"mozilla-devel-1.7.12-1.4.2.centos4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"mozilla-dom-inspector-1.7.12-1.4.2.centos4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"mozilla-js-debugger-1.7.12-1.4.2.centos4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"mozilla-mail-1.7.12-1.4.2.centos4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"mozilla-nspr-1.7.12-1.4.2.centos4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"mozilla-nspr-devel-1.7.12-1.4.2.centos4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"mozilla-nss-1.7.12-1.4.2.centos4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"mozilla-nss-devel-1.7.12-1.4.2.centos4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
