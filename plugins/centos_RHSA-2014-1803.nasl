#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1803 and 
# CentOS Errata and Security Advisory 2014:1803 respectively.
#

include("compat.inc");

if (description)
{
  script_id(78876);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/11/17 12:13:04 $");

  script_cve_id("CVE-2014-8566", "CVE-2014-8567");
  script_bugtraq_id(70893, 70896);
  script_xref(name:"RHSA", value:"2014:1803");

  script_name(english:"CentOS 6 : mod_auth_mellon (CESA-2014:1803)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated mod_auth_mellon package that fixes two security issues is
now available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having Important
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

mod_auth_mellon provides a SAML 2.0 authentication module for the
Apache HTTP Server.

An information disclosure flaw was found in mod_auth_mellon's session
handling that could lead to sessions overlapping in memory. A remote
attacker could potentially use this flaw to obtain data from another
user's session. (CVE-2014-8566)

It was found that uninitialized data could be read when processing a
user's logout request. By attempting to log out, a user could possibly
cause the Apache HTTP Server to crash. (CVE-2014-8567)

Red Hat would like to thank the mod_auth_mellon team for reporting
these issues. Upstream acknowledges Matthew Slowe as the original
reporter of CVE-2014-8566.

All users of mod_auth_mellon are advised to upgrade to this updated
package, which contains a backported patch to correct these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2014-November/020737.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d48153f9"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mod_auth_mellon package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mod_auth_mellon");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"mod_auth_mellon-0.8.0-3.el6_6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
