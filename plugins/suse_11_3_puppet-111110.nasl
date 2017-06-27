#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update puppet-5403.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75715);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:55:23 $");

  script_cve_id("CVE-2011-3848", "CVE-2011-3869", "CVE-2011-3870", "CVE-2011-3871", "CVE-2011-3872");

  script_name(english:"openSUSE Security Update : puppet (openSUSE-SU-2011:1288-1)");
  script_summary(english:"Check for the puppet-5403 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Puppet's certificate authority issued Puppet agent certificates
capable of impersonating the Puppet master. Compromised or rogue
puppet agents could therefore use their certificates for MITM attacks
(CVE-2011-3872). 

Note: If you've set the 'certdnsnames' option in your master's
puppet.conf file merely installing the updated packages is not
sufficient to fix this problem. You need to either pick a new DNS name
for the master and reconfigure all agents to use it or re-new
certificates on all agents.

Please refer to the documentation in
/usr/share/doc/packages/puppet/puppetlabs-cve20113872-0.0.5 for
detailed instructions and scripts. 

Puppetlabs' site also provides more information:
http://puppetlabs.com/security/cve/cve-2011-3872/faq/
http://puppetlabs.com/blog/important-security-announcement-altnames-vu
lnerability/

--

Directory traversal vulnerability in puppet allowed unauthenticated
remote attackers to upload x.509 certificate signing requests to
arbitrary locations (CVE-2011-3848)

Puppet was prone to several symlink attacks (CVE-2011-3870,
CVE-2011-3869, CVE-2011-3871)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2011-11/msg00027.html"
  );
  # http://puppetlabs.com/blog/important-security-announcement-altnames-vulnerability/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7c17e853"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://puppetlabs.com/security/cve/cve-2011-3872/faq/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=721139"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=726372"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=727024"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=727025"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected puppet packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:puppet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:puppet-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE11\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.3", reference:"puppet-0.25.4-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"puppet-server-0.25.4-4.7.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "puppet / puppet-server");
}
