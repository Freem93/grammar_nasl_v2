#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2016-de55d2c2c9.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(93060);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2017/04/26 13:35:46 $");

  script_cve_id("CVE-2016-5410");
  script_xref(name:"FEDORA", value:"2016-de55d2c2c9");

  script_name(english:"Fedora 24 : firewalld (2016-de55d2c2c9)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Fix CVE-2016-5410: Firewall configuration can be
    modified by any logged in user

  - firewall/server/firewalld: Make getXSettings and
    getLogDenied CONFIG_INFO

  - Update AppData configuration file.

  - tests/firewalld_rich.py: Use new import structure and
    FirewallClient classes

  - tests/firewalld_direct.py: Use new import structure

  - tests: firewalld_direct: Fix assert to check for True
    instead of False

  - tests: firewalld_config: Fix expected value when
    querying the zone target

  - tests: firewalld_config: Use real nf_conntrack modules

  - firewalld.spec: Added comment about make call for %build

  - firewall-config: Use also width_request and
    height_request with default size

  - Updated firewall-config screenshot

  - firewall-cmd: Fixed typo in help output (RHBZ#1367171)

  - test-suite: Ignore stderr to get default zone also for
    missing firewalld.conf

  - firewall.core.logger: Warnings should be printed to
    stderr per default

  - firewall.core.fw_nm: Ignore NetworkManager if NM.Client
    connect fails

  - firewall-cmd, firewallctl: Gracefully fail if SystemBus
    can not be aquired

  - firewall.client: Generate new DBUS_ERROR if SystemBus
    can not be aquired

  - test-suite: Do not fail on ALREADY_ENABLED
    --add-destination tests

  - firewall.command: ALREADY_ENABLED, NOT_ENABLED,
    ZONE_ALREADY_SET are warnings

  - doc/xml/firewalld.dbus.xml: Removed undefined reference

  - doc/xml/transform-html.xsl.in: Fixed references in the
    document

  - doc/xml/firewalld.{dbus,zone}.xml: Embed programlisting
    in para

  - doc/xml/transform-html.xsl.in: Enhanced html formatting
    closer to the man page

  - firewall: core: fw_nm: Instantiate the NM client only
    once

  - firewall/core/io/*.py: Do not traceback on a general sax
    parsing issue

  - firewall-offline-cmd: Fix
    --{add,remove}-entries-from-file

  - firewall-cmd: Add missing action to fix
    --{add,remove}-entries-from-file

  - firewall.core.prog: Do not output stderr, but return it
    in the error case

  - firewall.core.io.ifcfg.py: Fix ifcfg file reader and
    writer (RHBZ#1362171)

  - config/firewall.service.in: use KillMode=mixed

  - config/firewalld.service.in: use network-pre.target

  - firewall-config: Add missing gettext.textdomain call to
    fix translations

  - Add UDP to transmission-client.xml service

  - tests/firewall-[offline-]cmd_test.sh: Hide errors and
    warnings

  - firewall.client: Fix ALREADY_ENABLED errors in icmptype
    destination calls

  - firewall.client: Fix NOT_ENABLED errors in icmptype
    destination calls

  - firewall.client: Use {ALREADY,NOT}_ENABLED errors in
    icmptype destination calls

  - firewall.command: Add the removed FirewallError handling
    to the action (a17ce50)

  - firewall.command: Do not use query methods for sequences
    and also single options

  - Add missing information about MAC and ipset sources to
    man pages and help output

  - firewalld.spec: Add BuildRequires for libxslt to enable
    rebuild of man pages

  - firewall[-offline]-cmd, firewallctl, firewall.command:
    Use sys.{stdout,stderr}

  - firewallctl: Fix traceback if not connected to firewalld

  - firewall-config: Initialize value in
    on_richRuleDialogElementChooser_clicked

  - firewall.command: Convert errors to string for Python3

  - firewall.command: Get proper firewall error code from
    D-BusExceptions

  - firewall-cmd: Fixed traceback without args

  - Add missing service files to Makefile.am

  - shell-completion: Add shell completion support for

    --{get,set}--{description,short}

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2016-de55d2c2c9"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firewalld package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:firewalld");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:24");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^24([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 24", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC24", reference:"firewalld-0.4.3.3-1.fc24")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "firewalld");
}
