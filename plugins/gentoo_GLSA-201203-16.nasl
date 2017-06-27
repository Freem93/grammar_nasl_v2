#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201203-16.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(58381);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/04/13 14:19:44 $");

  script_cve_id("CVE-2011-1574", "CVE-2011-2911", "CVE-2011-2912", "CVE-2011-2913", "CVE-2011-2914", "CVE-2011-2915");
  script_bugtraq_id(47248, 48979);
  script_osvdb_id(72143, 74208, 74209, 74210, 74211);
  script_xref(name:"GLSA", value:"201203-16");

  script_name(english:"GLSA-201203-16 : ModPlug: User-assisted execution of arbitrary code");
  script_summary(english:"Checks for updated package(s) in /var/db/pkg");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Gentoo host is missing one or more security-related
patches."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote host is affected by the vulnerability described in GLSA-201203-16
(ModPlug: User-assisted execution of arbitrary code)

    Multiple vulnerabilities have been found in ModPlug:
      The ReadS3M method in load_s3m.cpp fails to validate user-supplied
        information, which could cause a stack-based buffer overflow
        (CVE-2011-1574).
      The 'CSoundFile::ReadWav()' function in load_wav.cpp contains an
        integer overflow which could cause a heap-based buffer overflow
        (CVE-2011-2911).
      The 'CSoundFile::ReadS3M()' function in load_s3m.cpp contains
        multiple boundary errors which could cause a stack-based buffer
        overflow (CVE-2011-2912).
      The 'CSoundFile::ReadAMS()' function in load_ams.cpp contains an
        off-by-one error which could cause memory corruption (CVE-2011-2913).
      The 'CSoundFile::ReadDSM()' function in load_dms.cpp contains an
        off-by-one error which could cause memory corruption (CVE-2011-2914).
      The 'CSoundFile::ReadAMS2()' function in load_ams.cpp contains an
        off-by-one error which could cause memory corruption (CVE-2011-2915).
  
Impact :

    A remote attacker could entice a user to open a specially crafted media
      file, possibly resulting in execution of arbitrary code, or a Denial of
      Service condition.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201203-16"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All ModPlug users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=media-libs/libmodplug-0.8.8.4'
    NOTE: This is a legacy GLSA. Updates for all affected architectures are
      available since August 27, 2011. It is likely that your system is already
      no longer affected by this issue."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'VideoLAN VLC ModPlug ReadS3M Stack Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'White_Phosphorus');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:libmodplug");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
  script_family(english:"Gentoo Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("qpkg.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Gentoo/release")) audit(AUDIT_OS_NOT, "Gentoo");
if (!get_kb_item("Host/Gentoo/qpkg-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;

if (qpkg_check(package:"media-libs/libmodplug", unaffected:make_list("ge 0.8.8.4"), vulnerable:make_list("lt 0.8.8.4"))) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:qpkg_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ModPlug");
}
