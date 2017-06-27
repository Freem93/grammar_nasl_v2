#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2017-c629f16f6c.
#

include("compat.inc");

if (description)
{
  script_id(96360);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/01/10 18:05:24 $");

  script_cve_id("CVE-2016-8734");
  script_xref(name:"FEDORA", value:"2017-c629f16f6c");

  script_name(english:"Fedora 25 : subversion (2017-c629f16f6c)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update includes the latest stable release of _Apache Subversion_,
version **1.9.5**.

#### Client-side bugfixes :

  - fix accessing non-existent paths during reintegrate
    merge 

  - fix handling of newly secured subdirectories in working
    copy 

  - info: remove trailing whitespace in --show-item=revision
    ([issue
    4660](http://subversion.tigris.org/issues/show_bug.cgi?i
    d=4660))

  - fix recording wrong revisions for tree conflicts 

  - gpg-agent: improve discovery of gpg-agent sockets 

  - gpg-agent: fix file descriptor leak 

  - resolve: fix --accept=mine-full for binary files ([issue
    4647](http://subversion.tigris.org/issues/show_bug.cgi?i
    d=4647))

  - merge: fix possible crash ([issue
    4652](http://subversion.tigris.org/issues/show_bug.cgi?i
    d=4652))

  - resolve: fix possible crash 

  - fix potential crash in Win32 crash reporter ####
    Server-side bugfixes :

  - fsfs: fix 'offset too large' error during pack ([issue
    4657](http://subversion.tigris.org/issues/show_bug.cgi?i
    d=4657))

  - svnserve: enable hook script environments 

  - fsfs: fix possible data reconstruction error ([issue
    4658](http://subversion.tigris.org/issues/show_bug.cgi?i
    d=4658))

  - fix source of spurious 'incoming edit' tree conflicts 

  - fsfs: improve caching for large directories 

  - fsfs: fix crash when encountering all-zero checksums 

  - fsfs: fix potential source of repository corruptions 

  - mod_dav_svn: fix excessive memory usage with
    mod_headers/mod_deflate ([issue
    3084](http://subversion.tigris.org/issues/show_bug.cgi?i
    d=3084))

  - mod_dav_svn: reduce memory usage during GET requests 

  - fsfs: fix unexpected 'database is locked' errors 

  - fsfs: fix opening old repositories without db/format
    files #### Client-side and server-side bugfixes :

  - fix possible crash when reading invalid configuration
    files #### Bindings bugfixes :

  - swig-pl: do not corrupt '{DATE}' revision variable 

  - javahl: fix temporary accepting SSL server certificates 

  - swig-pl: fix possible stack corruption

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2017-c629f16f6c"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected subversion package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:subversion");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:25");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^25([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 25", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC25", reference:"subversion-1.9.5-1.fc25")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "subversion");
}
