#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle Third Party software advisories.
#
include("compat.inc");

if (description)
{
  script_id(80731);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/08/17 14:24:38 $");

  script_cve_id("CVE-2004-0452", "CVE-2005-0156", "CVE-2005-0448", "CVE-2005-4278", "CVE-2010-1158", "CVE-2011-2939", "CVE-2012-5526");

  script_name(english:"Oracle Solaris Third-Party Patch Update : perl-58 (cve_2012_5526_configuration_vulnerability1)");
  script_summary(english:"Check for the 'entire' version.");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Solaris system is missing a security patch for third-party
software."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote Solaris system is missing necessary patches to address
security updates :

  - Race condition in the rmtree function in the File::Path
    module in Perl 5.6.1 and 5.8.4 sets read/write
    permissions for the world, which allows local users to
    delete arbitrary files and directories, and possibly
    read files and directories, via a symlink attack.
    (CVE-2004-0452)

  - Buffer overflow in the PerlIO implementation in Perl
    5.8.0, when installed with setuid support (sperl),
    allows local users to execute arbitrary code by setting
    the PERLIO_DEBUG variable and executing a Perl script
    whose full pathname contains a long directory tree.
    (CVE-2005-0156)

  - Race condition in the rmtree function in File::Path.pm
    in Perl before 5.8.4 allows local users to create
    arbitrary setuid binaries in the tree being deleted, a
    different vulnerability than CVE-2004-0452.
    (CVE-2005-0448)

  - Untrusted search path vulnerability in Perl before
    5.8.7-r1 on Gentoo Linux allows local users in the
    portage group to gain privileges via a malicious shared
    object in the Portage temporary build directory, which
    is part of the RUNPATH. (CVE-2005-4278)

  - Integer overflow in the regular expression engine in
    Perl 5.8.x allows context-dependent attackers to cause a
    denial of service (stack consumption and application
    crash) by matching a crafted regular expression against
    a long string. (CVE-2010-1158)

  - Off-by-one error in the decode_xs function in
    Unicode/Unicode.xs in the Encode module before 2.44, as
    used in Perl before 5.15.6, might allow
    context-dependent attackers to cause a denial of service
    (memory corruption) via a crafted Unicode string, which
    triggers a heap-based buffer overflow. (CVE-2011-2939)

  - CGI.pm module before 3.63 for Perl does not properly
    escape newlines in (1) Set-Cookie or (2) P3P headers,
    which might allow remote attackers to inject arbitrary
    headers into responses from applications that use
    CGI.pm. (CVE-2012-5526)"
  );
  # http://www.oracle.com/technetwork/topics/security/thirdparty-patch-map-1482893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5f8def1"
  );
  # https://blogs.oracle.com/sunsecurity/entry/cve_2012_5526_configuration_vulnerability1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?168d3dc0"
  );
  # https://blogs.oracle.com/sunsecurity/entry/multiple_vulnerabilities_in_perl_5
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?954882d7"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Solaris 11.1.11.4.0.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:perl-58");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris11/release", "Host/Solaris11/pkg-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/Solaris11/release");
if (isnull(release)) audit(AUDIT_OS_NOT, "Solaris11");
pkg_list = solaris_pkg_list_leaves();
if (isnull (pkg_list)) audit(AUDIT_PACKAGE_LIST_MISSING, "Solaris pkg-list packages");

if (empty_or_null(egrep(string:pkg_list, pattern:"^perl-58$"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "perl-58");

flag = 0;

if (solaris_check_release(release:"0.5.11-0.175.1.11.0.4.0", sru:"SRU 11.1.11.4.0") > 0) flag++;

if (flag)
{
  error_extra = 'Affected package : perl-58\n' + solaris_get_report2();
  error_extra = ereg_replace(pattern:"version", replace:"OS version", string:error_extra);
  if (report_verbosity > 0) security_hole(port:0, extra:error_extra);
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_PACKAGE_NOT_AFFECTED, "perl-58");
