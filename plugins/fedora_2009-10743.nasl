#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2009-10743.
#

include("compat.inc");

if (description)
{
  script_id(42378);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/05 16:01:14 $");

  script_bugtraq_id(36800);
  script_xref(name:"FEDORA", value:"2009-10743");
  script_xref(name:"Secunia", value:"37107");

  script_name(english:"Fedora 10 : squidGuard-1.4-8.fc10 (2009-10743)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Fixes language file issue, but more importantly. . . ---------------
squidGuard upstream has released patches fixing (quoting from upstream
advisories): a, This patch fixes one buffer overflow problem in
sgLog.c when overlong URLs are requested. SquidGuard will then go into
emergency mode were no blocking occurs. This is not required in this
situation. URL:
http://www.squidguard.org/Downloads/Patches/1.4/Readme.Patch-20091015
---- b, This patch fixes two bypass problems with URLs which length is
close to the limit defined by MAX_BUF (default: 4096) in squidGuard
and MAX_URL (default: 4096 in squid 2.x and 8192 in squid 3.x) in
squid. For this kind of URLs the proxy request exceeds MAX_BUF causing
squidGuard to complain about not being able to parse the squid
request. URL:
http://www.squidguard.org/Downloads/Patches/1.4/Readme.Patch-20091019
----

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://www.nntpnews.net/f3468/ports-139844-maintainer-update-www-squidguard-fix-
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?83b9c31a"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.securityfocus.com/bid/36800/info"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.squidguard.org/Downloads/Patches/1.4/Readme.Patch-20091015"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.squidguard.org/Downloads/Patches/1.4/Readme.Patch-20091019"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-November/030668.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fe7335ea"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected squidGuard package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:squidGuard");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:10");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^10([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 10.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC10", reference:"squidGuard-1.4-8.fc10")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "squidGuard");
}
