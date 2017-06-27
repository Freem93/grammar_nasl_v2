# @DEPRECATED@
#
# This script has been deprecated by vmware_VMSA-2008-0010.nasl.
#
# Disabled on 2011/09/19.

#
# (C) Tenable Network Security, Inc.
#
# The text of this plugin is (C) VMware Inc.
#

if (NASL_LEVEL < 3000) exit(0);
if (!defined_func("bn_random")) exit(0);

include("compat.inc");


if (description)
{
  script_id(40371);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2012/04/26 16:33:49 $");

  script_cve_id("CVE-2007-5232", "CVE-2007-5236", "CVE-2007-5237", "CVE-2007-5238", "CVE-2007-5239", "CVE-2007-5240", "CVE-2007-5274", "CVE-2007-5333", "CVE-2007-5342", "CVE-2007-5461", "CVE-2007-5689", "CVE-2007-6286", "CVE-2008-0657", "CVE-2008-1185", "CVE-2008-1186", "CVE-2008-1187", "CVE-2008-1188", "CVE-2008-1189", "CVE-2008-1190", "CVE-2008-1191", "CVE-2008-1192", "CVE-2008-1193", "CVE-2008-1194", "CVE-2008-1195", "CVE-2008-1196");
  script_osvdb_id(37759, 37760, 37761, 37762, 37763, 37764, 37765, 38187, 39833, 40834, 41146, 41147, 41435, 41436, 42589, 42590, 42591, 42592, 42593, 42594, 42595, 42596, 42597, 42598, 42599, 42600, 42601, 42602, 48610);

  script_name(english:"VMSA-2008-00010 : Updated Tomcat and Java JRE packages for VMware, ESX 3.5 and VirtualCenter 2.5 (DEPRECATED)");
  script_summary(english:"Looks for patch(es) in esxupdate output");

  script_set_attribute(
    attribute:"synopsis", 
    value: 
"The remote VMware host is missing one or more security-related 
patches."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated ESX patches and VirtualCenter update 2 fix the following
application vulnerabilities.

a. Tomcat Server Security Update

This release of ESX updates the Tomcat Server package to version
5.5.26, which addresses multiple security issues that existed
in earlier releases of Tomcat Server.

The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the names CVE-2007-5333, CVE-2007-5342, CVE-2007-5461,
CVE-2007-6286 to the security issues fixed in Tomcat 5.5.26.

b. JRE Security Update

This release of ESX and VirtualCenter updates the JRE package
to version 1.5.0_15, which addresses multiple security issues
that existed in earlier releases of JRE.

The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the names CVE-2008-1185, CVE-2008-1186, CVE-2008-1187,
CVE-2008-1188, CVE-2008-1189, CVE-2008-1190, CVE-2008-1191,
CVE-2008-1192, CVE-2008-1193, CVE-2008-1194, CVE-2008-1195,
CVE-2008-1196, CVE-2008-0657, CVE-2007-5689, CVE-2007-5232,
CVE-2007-5236, CVE-2007-5237, CVE-2007-5238, CVE-2007-5239,
CVE-2007-5240, CVE-2007-5274 to the security issues fixed in
JRE 1.5.0_12, JRE 1.5.0_13, JRE 1.5.0_14, JRE 1.5.0_15.

Notes: These vulnerabilities can be exploited remotely only if the
attacker has access to the service console network.
Security best practices provided by VMware recommend that the
service console be isolated from the VM network. Please see
http://www.vmware.com/resources/techresources/726 for more
information on VMware security best practices."
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.vmware.com/security/advisories/VMSA-2008-0010.html"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://lists.vmware.com/pipermail/security-announce/2008/000031.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patch(es).");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:emc:vmware");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/06/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is (C) 2009-2012 Tenable Network Security, Inc.");
  script_family(english:"VMware ESX Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/VMware/version");

  exit(0);
}

# Deprecated.
exit(0, "This plugin has been deprecated. Refer to plugin #40379 (vmware_VMSA-2008-0010.nasl) instead.");
