#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2012-1598.
#

include("compat.inc");

if (description)
{
  script_id(58050);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/10/20 22:34:52 $");

  script_cve_id("CVE-2011-3368", "CVE-2011-3607", "CVE-2012-0021", "CVE-2012-0031", "CVE-2012-0053");
  script_bugtraq_id(49957, 50494, 51407, 51705, 51706);
  script_xref(name:"FEDORA", value:"2012-1598");

  script_name(english:"Fedora 16 : httpd-2.2.22-1.fc16 (2012-1598)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update contains the latest stable release of the Apace HTTP
Server, version 2.2.22. This release fixes various bugs, and the
following security issues :

  - Reject requests where the request-URI does not match the
    HTTP specification, preventing unexpected expansion of
    target URLs in some reverse proxy configurations.
    (CVE-2011-3368)

  - Fix integer overflow in ap_pregsub() which, when the
    mod_setenvif module is enabled, could allow local users
    to gain privileges via a .htaccess file. (CVE-2011-3607)

  - Resolve additional cases of URL rewriting with
    ProxyPassMatch or RewriteRule, where particular
    request-URIs could result in undesired backend network
    exposure in some configurations. (CVE-2011-4317)

  - mod_log_config: Fix segfault (crash) when the
    '%{cookiename}C' log format string is in use and a
    client sends a nameless, valueless cookie, causing a
    denial of service. The issue existed since version
    2.2.17. (CVE-2012-0021)

  - Fix scoreboard issue which could allow an unprivileged
    child process could cause the parent to crash at
    shutdown rather than terminate cleanly. (CVE-2012-0031)

  - Fixed an issue in error responses that could expose
    'httpOnly' cookies when no custom ErrorDocument is
    specified for status code 400. (CVE-2012-0053)

http://www.apache.org/dist/httpd/CHANGES_2.2.22

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.apache.org/dist/httpd/CHANGES_2.2.22"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=785070"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-February/073489.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ec1cc0a9"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected httpd package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:httpd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:16");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = eregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! ereg(pattern:"^16([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 16.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC16", reference:"httpd-2.2.22-1.fc16")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "httpd");
}
