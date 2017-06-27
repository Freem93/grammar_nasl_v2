#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2016-53e8aa35f6.
#

include("compat.inc");

if (description)
{
  script_id(94121);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2017/03/13 15:28:55 $");

  script_cve_id("CVE-2013-5653", "CVE-2016-7976", "CVE-2016-7977", "CVE-2016-7978", "CVE-2016-7979");
  script_xref(name:"FEDORA", value:"2016-53e8aa35f6");

  script_name(english:"Fedora 24 : ghostscript (2016-53e8aa35f6)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This is a rebase of **ghostscript** package, to address several
security issues :

  - [CVE-2016-7977
    ](https://bugzilla.redhat.com/show_bug.cgi?id=1380415) -
    *.libfile does not honor -dSAFER*

  -
    [CVE-2013-5653](https://bugzilla.redhat.com/show_bug.cgi
    ?id=1380327) - *getenv and filenameforall ignore
    -dSAFER*

  -
    [CVE-2016-7976](https://bugzilla.redhat.com/show_bug.cgi
    ?id=1382294) - *various userparams allow %pipe% in
    paths, allowing remote shell*

  -
    [CVE-2016-7978](https://bugzilla.redhat.com/show_bug.cgi
    ?id=1382300) - *reference leak in .setdevice allows
    use-after-free and remote code*

  -
    [CVE-2016-7979](https://bugzilla.redhat.com/show_bug.cgi
    ?id=1382305) - *Type confusion in .initialize_dsc_parser
    allows remote code execution*

----------- #### INFORMATION FOR FEDORA PACKAGERS & MAINTAINERS :

**ghostscript** has been rebased to latest upstream version (9.20).
Rebase notes :

  - **no API/ABI changes between versions 9.16 -> 9.20
    according to upstream**

  - *OpenJPEG* support has been retained

  - *ijs-config* custom tool from upstream has been
    *removed* (by upstream) (*pkg-config* is used by default
    now instead, see [commit
    0c176a9](http://git.ghostscript.com/?p=ghostpdl.git;h=0c
    176a91d53c85cda))

  - some patches were updated to 'git format-patch' format &
    renamed

  - rest of the patches were deleted (irrelevant for current
    version), mostly because upstream has fixed those issues
    in some way

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2016-53e8aa35f6"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1380327"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1380415"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1382294"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1382300"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1382305"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ghostscript package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ghostscript");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:24");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/19");
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
if (rpm_check(release:"FC24", reference:"ghostscript-9.20-2.fc24")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ghostscript");
}
