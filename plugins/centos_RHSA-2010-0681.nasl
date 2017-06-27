#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0681 and 
# CentOS Errata and Security Advisory 2010:0681 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(49182);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/04 14:30:42 $");

  script_cve_id("CVE-2010-2753", "CVE-2010-2760", "CVE-2010-2762", "CVE-2010-2763", "CVE-2010-2764", "CVE-2010-2765", "CVE-2010-2766", "CVE-2010-2767", "CVE-2010-2768", "CVE-2010-2769", "CVE-2010-2770", "CVE-2010-3166", "CVE-2010-3167", "CVE-2010-3168", "CVE-2010-3169");
  script_bugtraq_id(43045);
  script_osvdb_id(66601, 67900, 67901, 67902, 67903, 67904, 67905, 67906, 67907, 67908, 67910, 67911, 67912, 67913);
  script_xref(name:"RHSA", value:"2010:0681");

  script_name(english:"CentOS 4 / 5 : firefox (CESA-2010:0681)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated firefox packages that fix several security issues are now
available for Red Hat Enterprise Linux 4 and 5.

The Red Hat Security Response Team has rated this update as having
critical security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Mozilla Firefox is an open source web browser. XULRunner provides the
XUL Runtime environment for Mozilla Firefox.

Several flaws were found in the processing of malformed web content. A
web page containing malicious content could cause Firefox to crash or,
potentially, execute arbitrary code with the privileges of the user
running Firefox. (CVE-2010-3169, CVE-2010-2762)

Several use-after-free and dangling pointer flaws were found in
Firefox. A web page containing malicious content could cause Firefox
to crash or, potentially, execute arbitrary code with the privileges
of the user running Firefox. (CVE-2010-2760, CVE-2010-2766,
CVE-2010-2767, CVE-2010-3167, CVE-2010-3168)

Multiple buffer overflow flaws were found in Firefox. A web page
containing malicious content could cause Firefox to crash or,
potentially, execute arbitrary code with the privileges of the user
running Firefox. (CVE-2010-2765, CVE-2010-3166)

Multiple cross-site scripting (XSS) flaws were found in Firefox. A web
page containing malicious content could cause Firefox to run
JavaScript code with the permissions of a different website.
(CVE-2010-2768, CVE-2010-2769)

A flaw was found in the Firefox XMLHttpRequest object. A remote site
could use this flaw to gather information about servers on an internal
private network. (CVE-2010-2764)

For technical details regarding these flaws, refer to the Mozilla
security advisories for Firefox 3.6.9. You can find a link to the
Mozilla advisories in the References section of this erratum.

Note: After installing this update, Firefox will fail to connect (with
HTTPS) to a server using the SSL DHE (Diffie-Hellman Ephemeral) key
exchange if the server's ephemeral key is too small. Connecting to
such servers is a security risk as an ephemeral key that is too small
makes the SSL connection vulnerable to attack. Refer to the Solution
section for further information.

All Firefox users should upgrade to these updated packages, which
contain Firefox version 3.6.9, which corrects these issues. After
installing the update, Firefox must be restarted for the changes to
take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-September/016968.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6c7c6eca"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-September/016969.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?98f5419a"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-September/016976.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e855d4db"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-September/016977.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?27f6c2d1"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firefox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nspr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-pkcs11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xulrunner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xulrunner-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/12");
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
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"firefox-3.6.9-1.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"firefox-3.6.9-1.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"nspr-4.8.6-1.el4_8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"nspr-4.8.6-1.el4_8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"nspr-devel-4.8.6-1.el4_8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"nspr-devel-4.8.6-1.el4_8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"nss-3.12.7-1.el4_8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"nss-3.12.7-1.el4_8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"nss-devel-3.12.7-1.el4_8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"nss-devel-3.12.7-1.el4_8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"nss-tools-3.12.7-1.el4_8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"nss-tools-3.12.7-1.el4_8")) flag++;

if (rpm_check(release:"CentOS-5", reference:"firefox-3.6.9-2.el5.centos")) flag++;
if (rpm_check(release:"CentOS-5", reference:"nspr-4.8.6-1.el5_5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"nspr-devel-4.8.6-1.el5_5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"nss-3.12.7-2.el5.centos")) flag++;
if (rpm_check(release:"CentOS-5", reference:"nss-devel-3.12.7-2.el5.centos")) flag++;
if (rpm_check(release:"CentOS-5", reference:"nss-pkcs11-devel-3.12.7-2.el5.centos")) flag++;
if (rpm_check(release:"CentOS-5", reference:"nss-tools-3.12.7-2.el5.centos")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xulrunner-1.9.2.9-1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xulrunner-devel-1.9.2.9-1.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
