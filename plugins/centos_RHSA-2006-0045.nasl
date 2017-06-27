#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0045 and 
# CentOS Errata and Security Advisory 2006:0045 respectively.
#

include("compat.inc");

if (description)
{
  script_id(21879);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2013/06/28 23:40:40 $");

  script_cve_id("CVE-2005-2917");
  script_xref(name:"RHSA", value:"2006:0045");

  script_name(english:"CentOS 3 : squid (CESA-2006:0045)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated squid packages that fix a security vulnerability as well as
several bugs are now available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Squid is a high-performance proxy caching server for Web clients,
supporting FTP, gopher, and HTTP data objects.

A denial of service flaw was found in the way squid processes certain
NTLM authentication requests. A remote attacker could send a specially
crafted NTLM authentication request which would cause the Squid server
to crash. The Common Vulnerabilities and Exposures project assigned
the name CVE-2005-2917 to this issue.

Several bugs have also been addressed in this update :

* An error introduced in 2.5.STABLE3-6.3E.14 where Squid can crash if
a user visits a site which has a long DNS record.

* Some authentication helpers were missing needed setuid rights.

* Squid couldn't handle a reply from a HTTP server when the reply
began with the new-line character or wasn't HTTP/1.0 or HTTP/1.1
compliant.

* User-defined error pages were not kept when the squid package was
upgraded.

All users of squid should upgrade to these updated packages, which
contain backported patches to resolve these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-March/012742.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?862693bb"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-March/012743.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?41e4ae26"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-March/012759.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c98ea69f"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected squid package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:squid");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-3", reference:"squid-2.5.STABLE3-6.3E.16")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
