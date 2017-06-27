#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2014-10975.
#

include("compat.inc");

if (description)
{
  script_id(77927);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/10/19 22:06:08 $");

  script_cve_id("CVE-2013-6668");
  script_bugtraq_id(65930);
  script_xref(name:"FEDORA", value:"2014-10975");

  script_name(english:"Fedora 19 : nodejs-0.10.32-1.fc19 / v8-3.14.5.10-14.fc19 (2014-10975)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update provides the latest stable version of Node.js and
corresponding backports to the v8 package.

This update resolves CVE-2013-6668, which has only a minor impact
since Node.js is not typically used to execute untrusted JavaScript.
For more information on the fixed vulnerability, please see the CVE
bugs listed below.

Changes in this update include :

  - v8: fix a crash introduced by previous release (Fedor
    Indutny)

    - crypto: use domains for any callback-taking method
      (Chris Dickinson)

    - http: do not send `0rnrn` in TE HEAD responses (Fedor
      Indutny)

    - querystring: fix unescape override (Tristan Berger)

    - url: Add support for RFC 3490 separators (Mathias
      Bynens)

    - v8: backport CVE-2013-6668

    - cluster: disconnect should not be synchronous (Sam
      Roberts)

    - fs: fix fs.readFileSync fd leak when get RangeError
      (Jackson Tian)

    - stream: fix Readable.wrap objectMode falsy values
      (James Halliday)

    - timers: fix timers with non-integer delay hanging.
      (Julien Gilli)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1074737"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/139162.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c01fd320"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/139163.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?660b46f7"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected nodejs and / or v8 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nodejs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:v8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:19");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^19([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 19.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC19", reference:"nodejs-0.10.32-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"v8-3.14.5.10-14.fc19")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nodejs / v8");
}
