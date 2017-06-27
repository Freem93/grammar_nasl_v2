#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2012-17019.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(62828);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/10/20 22:34:52 $");

  script_xref(name:"FEDORA", value:"2012-17019");

  script_name(english:"Fedora 16 : pcp-3.6.9-1.fc16 (2012-17019)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Update to latest PCP sources, and resolve these bugzillas :

  - Fix pmcd sigsegv in NUMA/CPU indom setup (BZ 858384)

    - Fix sar2pcp uninitialised perl variable warning (BZ
      859117)

    - Fix pcp.py and pmcollectl with older python versions
      (BZ 852234)

  - Added the python PMAPI bindings and an initial python
    client in pmcollectl. Separate, new package exists for
    python libs for those platforms that split out packages
    (rpm, deb).

  - Added a pcp-testsuite package for those platforms that
    might want this (rpm, deb again, mainly)

  - Re-introduced the pcp/qa subdirectory in pcp and
    deprecated the external pcpqa git tree.

  - Fix potential buffer overflow in pmlogger host name
    handling.

    - Reworked the configure --prefix handling to be more
      like the rest of the open source world.

  - Ensure the __pmDecodeText ident parameter is always set
    Resolves Red Hat bugzilla bug #841306. new upstream
    release new upstream release

  - Added the python PMAPI bindings and an initial python
    client in pmcollectl. Separate, new package exists for
    python libs for those platforms that split out packages
    (rpm, deb).

  - Added a pcp-testsuite package for those platforms that
    might want this (rpm, deb again, mainly)

  - Re-introduced the pcp/qa subdirectory in pcp and
    deprecated the external pcpqa git tree.

  - Fix potential buffer overflow in pmlogger host name
    handling.

    - Reworked the configure --prefix handling to be more
      like the rest of the open source world.

  - Ensure the __pmDecodeText ident parameter is always set
    Resolves Red Hat bugzilla bug #841306. new upstream
    release

  - Added the python PMAPI bindings and an initial python
    client in pmcollectl. Separate, new package exists for
    python libs for those platforms that split out packages
    (rpm, deb).

  - Added a pcp-testsuite package for those platforms that
    might want this (rpm, deb again, mainly)

  - Re-introduced the pcp/qa subdirectory in pcp and
    deprecated the external pcpqa git tree.

  - Fix potential buffer overflow in pmlogger host name
    handling.

    - Reworked the configure --prefix handling to be more
      like the rest of the open source world.

  - Ensure the __pmDecodeText ident parameter is always set
    Resolves Red Hat bugzilla bug #841306.

  - Added the python PMAPI bindings and an initial python
    client in pmcollectl. Separate, new package exists for
    python libs for those platforms that split out packages
    (rpm, deb).

  - Added a pcp-testsuite package for those platforms that
    might want this (rpm, deb again, mainly)

  - Re-introduced the pcp/qa subdirectory in pcp and
    deprecated the external pcpqa git tree.

  - Fix potential buffer overflow in pmlogger host name
    handling.

    - Reworked the configure --prefix handling to be more
      like the rest of the open source world.

  - Ensure the __pmDecodeText ident parameter is always set
    Resolves Red Hat bugzilla bug #841306.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=841306"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=852234"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=858384"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=859117"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-November/091138.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7bfd6c41"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected pcp package.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:pcp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:16");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/07");
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
if (rpm_check(release:"FC16", reference:"pcp-3.6.9-1.fc16")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "pcp");
}
