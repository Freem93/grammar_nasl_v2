#%NASL_MIN_LEVEL 99999
# @DEPRECATED@
#
# This script has been deprecated as the associated patch is not
# currently a security fix.
#
# Disabled on 2012/09/06.
#

#
# (C) Tenable Network Security, Inc.
#
# This script was automatically generated from
# Mandriva Linux Security Advisory MDVA-2009:095.
#

if (!defined_func("bn_random")) exit(0);

include("compat.inc");

if (description)
{
  script_id(39357);
  script_version ("$Revision: 1.8 $"); 
  script_cvs_date("$Date: 2012/10/04 19:39:07 $");

  script_cve_id("CVE-2009-1195");

  script_name(english:"MDVA-2009:095 : apache");
  script_summary(english:"Checks for patch(es) in 'rpm -qa' output");

  script_set_attribute(attribute:"synopsis", value: 
"The remote Mandriva host is missing one or more security-related
patches.");
  script_set_attribute(attribute:"description", value:
"The CVE-2009-1195 patch broke the mod_perl build. Patches from
upstream svn has been applied to this update that fixes the issue.");
  script_set_attribute(attribute:"see_also", value:"http://www.mandriva.com/security/advisories?name=MDVA-2009:095");
  script_set_attribute(attribute:"solution", value:"Update the affected package(s).");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
 script_cwe_id(16);
  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux");
  script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/06/11");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Mandriva Local Security Checks");
 
  script_copyright(english:"This script is Copyright (C) 2009-2011 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Mandrake/release", "Host/Mandrake/rpm-list");

  exit(0);
}

# Deprecated.
exit(0, "The associated patch is not currently a security fix.");


include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
if (!get_kb_item("Host/Mandrake/release")) exit(0, "The host is not running Mandrake Linux.");
if (!get_kb_item("Host/Mandrake/rpm-list")) exit(1, "Could not get the list of packages.");

flag = 0;

if (rpm_check(reference:"apache-base-2.2.8-6.3mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-devel-2.2.8-6.3mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-htcacheclean-2.2.8-6.3mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mod_authn_dbd-2.2.8-6.3mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mod_cache-2.2.8-6.3mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mod_dav-2.2.8-6.3mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mod_dbd-2.2.8-6.3mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mod_deflate-2.2.8-6.3mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mod_disk_cache-2.2.8-6.3mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mod_file_cache-2.2.8-6.3mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mod_ldap-2.2.8-6.3mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mod_mem_cache-2.2.8-6.3mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mod_proxy-2.2.8-6.3mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mod_proxy_ajp-2.2.8-6.3mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mod_ssl-2.2.8-6.3mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-modules-2.2.8-6.3mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mod_userdir-2.2.8-6.3mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mpm-event-2.2.8-6.3mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mpm-itk-2.2.8-6.3mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mpm-prefork-2.2.8-6.3mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mpm-worker-2.2.8-6.3mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-source-2.2.8-6.3mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;

if (rpm_check(reference:"apache-base-2.2.8-6.3mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-devel-2.2.8-6.3mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-htcacheclean-2.2.8-6.3mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mod_authn_dbd-2.2.8-6.3mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mod_cache-2.2.8-6.3mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mod_dav-2.2.8-6.3mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mod_dbd-2.2.8-6.3mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mod_deflate-2.2.8-6.3mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mod_disk_cache-2.2.8-6.3mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mod_file_cache-2.2.8-6.3mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mod_ldap-2.2.8-6.3mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mod_mem_cache-2.2.8-6.3mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mod_proxy-2.2.8-6.3mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mod_proxy_ajp-2.2.8-6.3mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mod_ssl-2.2.8-6.3mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-modules-2.2.8-6.3mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mod_userdir-2.2.8-6.3mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mpm-event-2.2.8-6.3mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mpm-itk-2.2.8-6.3mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mpm-prefork-2.2.8-6.3mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mpm-worker-2.2.8-6.3mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-source-2.2.8-6.3mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;

if (rpm_check(reference:"apache-base-2.2.9-12.2mdv2009.0", release:"MDK2009.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-devel-2.2.9-12.2mdv2009.0", release:"MDK2009.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-htcacheclean-2.2.9-12.2mdv2009.0", release:"MDK2009.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mod_authn_dbd-2.2.9-12.2mdv2009.0", release:"MDK2009.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mod_cache-2.2.9-12.2mdv2009.0", release:"MDK2009.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mod_dav-2.2.9-12.2mdv2009.0", release:"MDK2009.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mod_dbd-2.2.9-12.2mdv2009.0", release:"MDK2009.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mod_deflate-2.2.9-12.2mdv2009.0", release:"MDK2009.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mod_disk_cache-2.2.9-12.2mdv2009.0", release:"MDK2009.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mod_file_cache-2.2.9-12.2mdv2009.0", release:"MDK2009.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mod_ldap-2.2.9-12.2mdv2009.0", release:"MDK2009.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mod_mem_cache-2.2.9-12.2mdv2009.0", release:"MDK2009.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mod_proxy-2.2.9-12.2mdv2009.0", release:"MDK2009.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mod_proxy_ajp-2.2.9-12.2mdv2009.0", release:"MDK2009.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mod_ssl-2.2.9-12.2mdv2009.0", release:"MDK2009.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-modules-2.2.9-12.2mdv2009.0", release:"MDK2009.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mod_userdir-2.2.9-12.2mdv2009.0", release:"MDK2009.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mpm-event-2.2.9-12.2mdv2009.0", release:"MDK2009.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mpm-itk-2.2.9-12.2mdv2009.0", release:"MDK2009.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mpm-peruser-2.2.9-12.2mdv2009.0", release:"MDK2009.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mpm-prefork-2.2.9-12.2mdv2009.0", release:"MDK2009.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mpm-worker-2.2.9-12.2mdv2009.0", release:"MDK2009.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-source-2.2.9-12.2mdv2009.0", release:"MDK2009.0", cpu:"i386", yank:"mdv")) flag++;

if (rpm_check(reference:"apache-base-2.2.9-12.2mdv2009.0", release:"MDK2009.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-devel-2.2.9-12.2mdv2009.0", release:"MDK2009.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-htcacheclean-2.2.9-12.2mdv2009.0", release:"MDK2009.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mod_authn_dbd-2.2.9-12.2mdv2009.0", release:"MDK2009.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mod_cache-2.2.9-12.2mdv2009.0", release:"MDK2009.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mod_dav-2.2.9-12.2mdv2009.0", release:"MDK2009.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mod_dbd-2.2.9-12.2mdv2009.0", release:"MDK2009.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mod_deflate-2.2.9-12.2mdv2009.0", release:"MDK2009.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mod_disk_cache-2.2.9-12.2mdv2009.0", release:"MDK2009.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mod_file_cache-2.2.9-12.2mdv2009.0", release:"MDK2009.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mod_ldap-2.2.9-12.2mdv2009.0", release:"MDK2009.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mod_mem_cache-2.2.9-12.2mdv2009.0", release:"MDK2009.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mod_proxy-2.2.9-12.2mdv2009.0", release:"MDK2009.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mod_proxy_ajp-2.2.9-12.2mdv2009.0", release:"MDK2009.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mod_ssl-2.2.9-12.2mdv2009.0", release:"MDK2009.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-modules-2.2.9-12.2mdv2009.0", release:"MDK2009.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mod_userdir-2.2.9-12.2mdv2009.0", release:"MDK2009.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mpm-event-2.2.9-12.2mdv2009.0", release:"MDK2009.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mpm-itk-2.2.9-12.2mdv2009.0", release:"MDK2009.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mpm-peruser-2.2.9-12.2mdv2009.0", release:"MDK2009.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mpm-prefork-2.2.9-12.2mdv2009.0", release:"MDK2009.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mpm-worker-2.2.9-12.2mdv2009.0", release:"MDK2009.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-source-2.2.9-12.2mdv2009.0", release:"MDK2009.0", cpu:"x86_64", yank:"mdv")) flag++;

if (rpm_check(reference:"apache-base-2.2.11-10.3mdv2009.1", release:"MDK2009.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-devel-2.2.11-10.3mdv2009.1", release:"MDK2009.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-htcacheclean-2.2.11-10.3mdv2009.1", release:"MDK2009.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mod_authn_dbd-2.2.11-10.3mdv2009.1", release:"MDK2009.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mod_cache-2.2.11-10.3mdv2009.1", release:"MDK2009.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mod_dav-2.2.11-10.3mdv2009.1", release:"MDK2009.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mod_dbd-2.2.11-10.3mdv2009.1", release:"MDK2009.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mod_deflate-2.2.11-10.3mdv2009.1", release:"MDK2009.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mod_disk_cache-2.2.11-10.3mdv2009.1", release:"MDK2009.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mod_file_cache-2.2.11-10.3mdv2009.1", release:"MDK2009.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mod_ldap-2.2.11-10.3mdv2009.1", release:"MDK2009.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mod_mem_cache-2.2.11-10.3mdv2009.1", release:"MDK2009.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mod_proxy-2.2.11-10.3mdv2009.1", release:"MDK2009.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mod_proxy_ajp-2.2.11-10.3mdv2009.1", release:"MDK2009.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mod_ssl-2.2.11-10.3mdv2009.1", release:"MDK2009.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-modules-2.2.11-10.3mdv2009.1", release:"MDK2009.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mod_userdir-2.2.11-10.3mdv2009.1", release:"MDK2009.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mpm-event-2.2.11-10.3mdv2009.1", release:"MDK2009.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mpm-itk-2.2.11-10.3mdv2009.1", release:"MDK2009.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mpm-peruser-2.2.11-10.3mdv2009.1", release:"MDK2009.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mpm-prefork-2.2.11-10.3mdv2009.1", release:"MDK2009.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mpm-worker-2.2.11-10.3mdv2009.1", release:"MDK2009.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-source-2.2.11-10.3mdv2009.1", release:"MDK2009.1", cpu:"i386", yank:"mdv")) flag++;

if (rpm_check(reference:"apache-base-2.2.11-10.3mdv2009.1", release:"MDK2009.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-devel-2.2.11-10.3mdv2009.1", release:"MDK2009.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-htcacheclean-2.2.11-10.3mdv2009.1", release:"MDK2009.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mod_authn_dbd-2.2.11-10.3mdv2009.1", release:"MDK2009.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mod_cache-2.2.11-10.3mdv2009.1", release:"MDK2009.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mod_dav-2.2.11-10.3mdv2009.1", release:"MDK2009.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mod_dbd-2.2.11-10.3mdv2009.1", release:"MDK2009.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mod_deflate-2.2.11-10.3mdv2009.1", release:"MDK2009.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mod_disk_cache-2.2.11-10.3mdv2009.1", release:"MDK2009.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mod_file_cache-2.2.11-10.3mdv2009.1", release:"MDK2009.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mod_ldap-2.2.11-10.3mdv2009.1", release:"MDK2009.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mod_mem_cache-2.2.11-10.3mdv2009.1", release:"MDK2009.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mod_proxy-2.2.11-10.3mdv2009.1", release:"MDK2009.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mod_proxy_ajp-2.2.11-10.3mdv2009.1", release:"MDK2009.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mod_ssl-2.2.11-10.3mdv2009.1", release:"MDK2009.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-modules-2.2.11-10.3mdv2009.1", release:"MDK2009.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mod_userdir-2.2.11-10.3mdv2009.1", release:"MDK2009.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mpm-event-2.2.11-10.3mdv2009.1", release:"MDK2009.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mpm-itk-2.2.11-10.3mdv2009.1", release:"MDK2009.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mpm-peruser-2.2.11-10.3mdv2009.1", release:"MDK2009.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mpm-prefork-2.2.11-10.3mdv2009.1", release:"MDK2009.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-mpm-worker-2.2.11-10.3mdv2009.1", release:"MDK2009.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"apache-source-2.2.11-10.3mdv2009.1", release:"MDK2009.1", cpu:"x86_64", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else 
{
  if (
    rpm_exists(rpm:"apache-", release:"MDK2008.1") ||
    rpm_exists(rpm:"apache-", release:"MDK2009.0") ||
    rpm_exists(rpm:"apache-", release:"MDK2009.1")
  )
  {
    set_kb_item(name:"CVE-2009-1195", value:TRUE);
  }

  exit(0, "The host is not affected.");
}
