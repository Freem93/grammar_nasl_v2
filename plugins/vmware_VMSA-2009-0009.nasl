#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2009-0009. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(52011);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/11/29 20:13:37 $");

  script_cve_id("CVE-2009-0034", "CVE-2009-0037", "CVE-2009-1185");
  script_bugtraq_id(33517, 33962, 34536);
  script_osvdb_id(51736, 53572, 53810);
  script_xref(name:"VMSA", value:"2009-0009");

  script_name(english:"VMSA-2009-0009 : ESX Service Console updates for udev, sudo, and curl");
  script_summary(english:"Checks esxupdate output for the patches");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote VMware ESX host is missing one or more security-related
patches."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"a. Service Console package udev

   A vulnerability in the udev program did not verify whether a NETLINK
   message originates from kernel space, which allows local users to
   gain privileges by sending a NETLINK message from user space.

   The Common Vulnerabilities and Exposures Project (cve.mitre.org)
   has assigned the name CVE-2009-1185 to this issue.

   Please see http://kb.vmware.com/kb/1011786 for details.

b. Service Console package sudo

   Service Console package for sudo has been updated to version
   sudo-1.6.9p17-3. This fixes the following issue: Sudo versions
   1.6.9p17 through 1.6.9p19 do not properly interpret a system group
   in the sudoers file during authorization decisions for a user who
   belongs to that group, which might allow local users to leverage an
   applicable sudoers file and gain root privileges by using a sudo
   command.

   The Common Vulnerabilities and Exposures Project (cve.mitre.org)
   has assigned the name CVE-2009-0034 to this issue.

   Please see http://kb.vmware.com/kb/1011781 for more details

c. Service Console package curl

   Service Console package for curl has been updated to version
   curl-7.15.5-2.1.  This fixes the following issue: The redirect
   implementation in curl and libcurl 5.11 through 7.19.3, when
   CURLOPT_FOLLOWLOCATION is enabled, accepts arbitrary Location
   values, which might allow remote HTTP servers to trigger arbitrary
   requests to intranet servers, read or overwrite arbitrary files by
   using a redirect to a file: URL, or execute arbitrary commands by
   using a redirect to an scp: URL.

   The Common Vulnerabilities and Exposures Project (cve.mitre.org)
   has assigned the name CVE-2009-0037 to this issue.

   Please see http://kb.vmware.com/kb/1011782 for details"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2009/000060.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patches.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Linux udev Netlink Local Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(20, 264, 352);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
  script_family(english:"VMware ESX Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/VMware/release", "Host/VMware/version");
  script_require_ports("Host/VMware/esxupdate", "Host/VMware/esxcli_software_vibs");

  exit(0);
}


include("audit.inc");
include("vmware_esx_packages.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/VMware/release")) audit(AUDIT_OS_NOT, "VMware ESX / ESXi");
if (
  !get_kb_item("Host/VMware/esxcli_software_vibs") &&
  !get_kb_item("Host/VMware/esxupdate")
) audit(AUDIT_PACKAGE_LIST_MISSING);


init_esx_check(date:"2009-07-10");
flag = 0;


if (
  esx_check(
    ver           : "ESX 4.0.0",
    patch         : "ESX400-200906406-SG",
    patch_updates : make_list("ESX400-201005409-SG", "ESX400-201009410-SG", "ESX400-201101404-SG", "ESX400-201305402-SG", "ESX400-Update01a", "ESX400-Update02", "ESX400-Update03", "ESX400-Update04")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 4.0.0",
    patch         : "ESX400-200906407-SG",
    patch_updates : make_list("ESX400-200911232-SG", "ESX400-201009409-SG", "ESX400-201203403-SG", "ESX400-Update01a", "ESX400-Update02", "ESX400-Update03", "ESX400-Update04")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 4.0.0",
    patch         : "ESX400-200906411-SG",
    patch_updates : make_list("ESX400-Update01a", "ESX400-Update02", "ESX400-Update03", "ESX400-Update04")
  )
) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:esx_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
