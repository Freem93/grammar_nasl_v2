#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2009-0017. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(52012);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2014/08/14 14:19:28 $");

  script_cve_id("CVE-2009-3731");
  script_bugtraq_id(37346);
  script_osvdb_id(61049, 61305, 61306, 61307, 61308);
  script_xref(name:"VMSA", value:"2009-0017");

  script_name(english:"VMSA-2009-0017 : VMware vCenter, ESX patch and vCenter Lab Manager releases address XSS issues");
  script_summary(english:"Checks esxupdate output for the patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote VMware ESX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"a. WebWorks Help - Cross-site scripting vulnerability

   WebWorks Help is an output format that allows online Help to be
   delivered on multiple platforms and browsers, which makes it easy
   to publish information on the Web or on an enterprise intranet.
   WebWorks Help is used for creating the online help pages that are
   available in VMware WebAccess, Lab Manager and Stage Manager.

   WebWorks Help doesn't sufficiently sanitize incoming requests which
   may result in cross-site scripting vulnerabilities in applications
   that are built with WebWorks Help.

   Exploitation of these vulnerabilities in VMware products requires
   tricking a user to click on a malicious link or to open a malicious
   web page while they are logged in into vCenter, ESX or VMware
   Server using WebAccess, or logged in into Stage Manager or Lab
   Manager.

   Successful exploitation can lead to theft of user credentials. These
   vulnerabilities can be exploited remotely only if the attacker has
   access to the Service Console network.

   Security best practices provided by VMware recommend that the
   Service Console be isolated from the VM network. Please see
   http://www.vmware.com/resources/techresources/726 for more
   information on VMware security best practices.

   Client-side protection measures included with current browsers are not
   always able to prevent these attacks from being executed.

   VMware would like to thank Daniel Grzelak and Alex Kouzemtchenko of
   stratsec (www.stratsec.net) for finding and reporting this issue.
   VMware would also like to thank Ben Allums of WebWorks.com for working
   on the remediation of this issue with us.

   The Common Vulnerabilities and Exposures project (cve.mitre.org) has
   assigned the name CVE-2009-3731 to this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2009/000073.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");
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


init_esx_check(date:"2009-12-15");
flag = 0;


if (
  esx_check(
    ver           : "ESX 4.0",
    patch         : "ESX400-200911223-UG",
    patch_updates : make_list("ESX400-Update01a", "ESX400-Update02", "ESX400-Update03", "ESX400-Update04")
  )
) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:esx_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
