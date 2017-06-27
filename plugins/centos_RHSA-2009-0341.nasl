#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:0341 and 
# CentOS Errata and Security Advisory 2009:0341 respectively.
#

include("compat.inc");

if (description)
{
  script_id(35965);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/04 14:30:41 $");

  script_cve_id("CVE-2009-0037");
  script_bugtraq_id(33962);
  script_xref(name:"RHSA", value:"2009:0341");

  script_name(english:"CentOS 3 / 4 : curl (CESA-2009:0341)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated curl packages that fix a security issue are now available for
Red Hat Enterprise Linux 2.1, 3, 4, and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

cURL is a tool for getting files from FTP, HTTP, Gopher, Telnet, and
Dict servers, using any of the supported protocols. cURL is designed
to work without user interaction or any kind of interactivity.

David Kierznowski discovered a flaw in libcurl where it would not
differentiate between different target URLs when handling automatic
redirects. This caused libcurl to follow any new URL that it
understood, including the 'file://' URL type. This could allow a
remote server to force a local libcurl-using application to read a
local file instead of the remote one, possibly exposing local files
that were not meant to be exposed. (CVE-2009-0037)

Note: Applications using libcurl that are expected to follow redirects
to 'file://' protocol must now explicitly call curl_easy_setopt(3) and
set the newly introduced CURLOPT_REDIR_PROTOCOLS option as required.

cURL users should upgrade to these updated packages, which contain
backported patches to correct these issues. All running applications
using libcurl must be restarted for the update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-April/015808.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?18f09f31"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-April/015809.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?940a59f8"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-March/015686.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0a612fd2"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-March/015687.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?de5f6bd2"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-March/015694.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b2add910"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-March/015695.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e513ae62"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected curl packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(352);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:curl-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/03/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-3", reference:"curl-7.10.6-9.rhel3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"curl-devel-7.10.6-9.rhel3")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"curl-7.12.1-11.1.el4_7.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"curl-7.12.1-11.1.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"curl-7.12.1-11.1.el4_7.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"curl-devel-7.12.1-11.1.el4_7.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"curl-devel-7.12.1-11.1.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"curl-devel-7.12.1-11.1.el4_7.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
