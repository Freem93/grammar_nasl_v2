#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2015-3079.
#

include("compat.inc");

if (description)
{
  script_id(82275);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/10/19 23:06:17 $");

  script_cve_id("CVE-2015-2172");
  script_bugtraq_id(72827);
  script_xref(name:"FEDORA", value:"2015-3079");

  script_name(english:"Fedora 22 : dokuwiki-0-0.24.20140929c.fc22 (2015-3079)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes CVE-2015-2172

  - There's a security hole in the ACL plugins remote API
    component. The plugin failes to check for superuser
    permissions before executing ACL addition or deletion.
    This means everybody with permissions to call the XMLRPC
    API also has permissions to set up their own ACL rules
    and thus circumventing any existing rules. Update to the
    2014-09-29b release which contains various fixes,
    notably :

Security :

  - CVE-2014-9253 - XSS via SFW file upload

    - CVE-2012-6662 - jquery-ui XSS vulnerability

Bugfixes :

  - dokuwiki requires php-xml (RHBZ#1061477)

    - wrong SELinux file context for writable
      files/directories (RHBZ#1064524)

    - drop httpd requirement (RHBZ#1164396)

Update to the 2014-09-29b release which contains various fixes,
notably :

Security :

  - CVE-2014-9253 - XSS via SFW file upload

    - CVE-2012-6662 - jquery-ui XSS vulnerability

Bugfixes :

  - dokuwiki requires php-xml (RHBZ#1061477)

    - wrong SELinux file context for writable
      files/directories (RHBZ#1064524)

    - drop httpd requirement (RHBZ#1164396)

Update to the 2014-09-29b release which contains various fixes,
notably :

Security :

  - CVE-2014-9253 - XSS via SFW file upload

    - CVE-2012-6662 - jquery-ui XSS vulnerability

Bugfixes :

  - dokuwiki requires php-xml (RHBZ#1061477)

    - wrong SELinux file context for writable
      files/directories (RHBZ#1064524)

    - drop httpd requirement (RHBZ#1164396)

Update to the 2014-09-29b release which contains various fixes,
notably :

Security :

  - CVE-2014-9253 - XSS via SFW file upload

    - CVE-2012-6662 - jquery-ui XSS vulnerability

Bugfixes :

  - dokuwiki requires php-xml (RHBZ#1061477)

    - wrong SELinux file context for writable
      files/directories (RHBZ#1064524)

    - drop httpd requirement (RHBZ#1164396)

This update adds dokuwiki package to EPEL7

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1197822"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-March/153266.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9f98f987"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected dokuwiki package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:dokuwiki");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:22");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^22([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 22.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC22", reference:"dokuwiki-0-0.24.20140929c.fc22")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dokuwiki");
}
